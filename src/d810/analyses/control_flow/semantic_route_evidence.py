"""Provider-neutral state-machine route proofs for canonical lowering."""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass, replace
from enum import Enum
import hashlib
import json
from types import MappingProxyType
from collections.abc import Mapping

from d810.core.logging import getLogger
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import (
    NativeEaInterval,
    StableBlockIdentity,
    stable_block_identity_semantic_anchor,
    stable_block_identities_refine_at_anchor,
    stable_block_identity_from_snapshot,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, OperandKind
from d810.ir.graph_fingerprint import (
    portable_graph_fingerprint,
    portable_graph_fingerprint_values,
)
from d810.ir.flowgraph import InsnKind
from d810.ir.insn_projection import (
    InstructionProjection,
    operand_storages,
    operand_stack_offsets,
    project_instruction_effect_sites,
    instruction_references_stack_identity,
    project_instruction,
)
from d810.analyses.control_flow.state_machine_analysis import (
    _transfer_snapshot_constant_block,
    run_snapshot_constant_fixpoint,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.ir.varnode import Space, varnode_from_mop_snapshot
from d810.ir.varnode import Varnode
from d810.ir.instructions import Instruction, InstructionEffectSite
from d810.ir.storage_identity import storage_identity_from_varnode
from d810.ir.expressions import ValueOpKind
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.analyses.control_flow.route_comparison import (
    current_u32_route_alias,
    current_u32_route_comparison,
)
from d810.analyses.control_flow.terminal_return_carrier_evidence import (
    TerminalReturnCarrierEvidence,
    TerminalReturnCarrierSourceKind,
)
from d810.analyses.control_flow.state_carrier import (
    ExactCarrierStateWrite,
    ExactStateTransformFeeder,
    prove_exact_u32_carrier_state_write,
    prove_exact_u32_state_delivery,
    prove_exact_u32_state_transform_feeder,
)


_BADADDR = 0xFFFFFFFFFFFFFFFF
logger = getLogger(__name__)


class SemanticRouteEvidenceRejected(ValueError):
    """Canonical route evidence is incomplete, ambiguous, or inconsistent."""


class SemanticRouteShape(str, Enum):
    """Complete semantic control-flow shape proved for one route owner."""

    DIRECT = "direct"
    CONDITIONAL = "conditional"


class SemanticRouteProofKind(str, Enum):
    """Provider-independent reason a canonical route is authoritative."""

    STATE_ASSIGNMENT = "state_assignment"
    STATE_TRANSFORM = "state_transform"
    STATE_CARRIER = "state_carrier"
    STATE_PARTITION = "state_partition"
    STATE_DAG = "state_dag"
    STATE_CHOICE = "state_choice"
    BOOTSTRAP = "bootstrap"
    TERMINAL_RETURN = "terminal_return"


class SemanticPredicateKind(str, Enum):
    """Portable strategy for realizing one complete conditional predicate."""

    PRESERVE_LIVE = "preserve_live"
    STORAGE_EQUALS = "storage_equals"


class SemanticStateWriteDeliveryKind(str, Enum):
    """Physical transfer already proven at a direct semantic route boundary."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    CONDITIONAL = "conditional"


class SemanticRouteFactKind(str, Enum):
    """Typed recovery oracle that can be promoted into one canonical proof."""

    DECISION_DAG = "decision_dag"
    NATIVE_BOUND = "native_bound"
    STATE_TRANSFORM = "state_transform"
    STATE_CARRIER = "state_carrier"
    STATE_PARTITION = "state_partition"
    BOOTSTRAP = "bootstrap"


@dataclass(frozen=True, slots=True)
class StatePartitionMemberWitness:
    """One predecessor-specific result of the shared feeder fixpoint."""

    owner_serial: int
    feeder_serial: int
    state_identity: StorageIdentity
    state_constant: int

    def __post_init__(self) -> None:
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("partition member requires state identity")
        object.__setattr__(self, "owner_serial", int(self.owner_serial))
        object.__setattr__(self, "feeder_serial", int(self.feeder_serial))
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)


@dataclass(frozen=True, slots=True)
class StatePartitionGroupWitness:
    """Complete sibling set sharing one exact feeder/store."""

    group_id: str
    feeder_serial: int
    feeder_instruction_ea: int
    state_identity: StorageIdentity
    members: tuple[StatePartitionMemberWitness, ...]

    def __post_init__(self) -> None:
        members = tuple(self.members)
        if not members or any(not isinstance(item, StatePartitionMemberWitness) for item in members):
            raise SemanticRouteEvidenceRejected("partition group requires members")
        owners = tuple(int(item.owner_serial) for item in members)
        if len(set(owners)) != len(owners) or any(
            int(item.feeder_serial) != int(self.feeder_serial)
            or item.state_identity != self.state_identity
            for item in members
        ):
            raise SemanticRouteEvidenceRejected("partition group members disagree")
        object.__setattr__(self, "group_id", _identifier(self.group_id, "partition group id"))
        object.__setattr__(self, "feeder_serial", int(self.feeder_serial))
        object.__setattr__(self, "feeder_instruction_ea", _native_ea(self.feeder_instruction_ea, "partition feeder write"))
        object.__setattr__(self, "members", members)


@dataclass(frozen=True, slots=True)
class SemanticBootstrapRouteWitness:
    """Raw entry-to-dispatcher witness for a bootstrap route."""

    entry_serial: int
    source_serial: int
    source_instruction_ea: int
    owner_serial: int
    dispatcher_serial: int
    state_identity: StorageIdentity
    state_constant: int
    state_width: int
    corridor_serials: tuple[int, ...]
    corridor_anchors: tuple[int, ...]
    preserved_effect_sites: tuple[InstructionEffectSite, ...]
    decision_dag_witness: "DecisionDagRouteWitness"

    def __post_init__(self) -> None:
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("bootstrap witness requires state identity")
        if not isinstance(self.decision_dag_witness, DecisionDagRouteWitness):
            raise TypeError("bootstrap witness requires decision-DAG witness")
        serials = tuple(int(serial) for serial in self.corridor_serials)
        anchors = tuple(_native_ea(ea, "bootstrap corridor anchor") for ea in self.corridor_anchors)
        if (
            not serials
            or len(serials) != len(anchors)
            or len(set(serials)) != len(serials)
            or serials[0] != int(self.source_serial)
            or serials[-1] != int(self.dispatcher_serial)
            or len(serials) < 2
            or serials[-2] != int(self.owner_serial)
        ):
            raise SemanticRouteEvidenceRejected("bootstrap corridor is incomplete")
        if int(self.state_width) != 4:
            raise SemanticRouteEvidenceRejected("bootstrap state write must be 4 bytes")
        effects = tuple(self.preserved_effect_sites)
        if any(not isinstance(site, InstructionEffectSite) for site in effects):
            raise TypeError("bootstrap preserved effects require typed effect sites")
        if effects != tuple(sorted(effects, key=lambda site: (site.instruction_ea, site.host_instruction_ea, site.kind.value))):
            raise SemanticRouteEvidenceRejected("bootstrap preserved effects must be ordered")
        if (
            self.decision_dag_witness.state_identity != self.state_identity
            or int(self.decision_dag_witness.state_constant) != (int(self.state_constant) & 0xFFFFFFFF)
        ):
            raise SemanticRouteEvidenceRejected("bootstrap DAG disagrees with state write")
        object.__setattr__(self, "entry_serial", int(self.entry_serial))
        object.__setattr__(self, "source_serial", int(self.source_serial))
        object.__setattr__(self, "source_instruction_ea", _native_ea(self.source_instruction_ea, "bootstrap state write"))
        object.__setattr__(self, "owner_serial", int(self.owner_serial))
        object.__setattr__(self, "dispatcher_serial", int(self.dispatcher_serial))
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)
        object.__setattr__(self, "state_width", int(self.state_width))
        object.__setattr__(self, "corridor_serials", serials)
        object.__setattr__(self, "corridor_anchors", anchors)
        object.__setattr__(self, "preserved_effect_sites", effects)


def prove_partitioned_state_member(
    flow_graph: FlowGraph,
    member: StatePartitionMemberWitness,
    *,
    feeder_instruction_ea: int,
    state_var_stkoff: int | None,
    state_var_reg: int | None,
    fixpoint: object | None = None,
) -> bool:
    """Replay one predecessor-specific state result through the shared feeder.

    The owner OUT store is recomputed from the immutable graph snapshot before
    the feeder transfer is replayed; no producer-supplied store is accepted.
    """
    owner = flow_graph.get_block(int(member.owner_serial))
    feeder = flow_graph.get_block(int(member.feeder_serial))
    if (
        owner is None
        or feeder is None
        or tuple(int(item) for item in owner.succs) != (int(member.feeder_serial),)
        or int(member.owner_serial) not in tuple(int(item) for item in feeder.preds)
    ):
        return False
    if not prove_exact_u32_state_delivery(
        flow_graph,
        int(member.owner_serial),
        int(member.feeder_serial),
        feeder_instruction_ea=int(feeder_instruction_ea),
        state_var_stkoff=state_var_stkoff,
        state_var_reg=state_var_reg,
        expected_state=int(member.state_constant),
    ):
        return False
    snapshot = tuple(
        item for item in feeder.insn_snapshots
        if int(item.native_ea or item.ea) == int(feeder_instruction_ea)
    )
    if len(snapshot) != 1:
        return False
    effective_stkoff = -1 if state_var_stkoff is None else int(state_var_stkoff)
    if fixpoint is None:
        fixpoint = run_snapshot_constant_fixpoint(flow_graph, effective_stkoff)
    actual_stack = tuple(
        sorted(
            (int(offset), int(value) & 0xFFFFFFFF)
            for offset, value in fixpoint.out_stk_maps.get(int(member.owner_serial), {}).items()
        )
    )
    actual_registers = tuple(
        sorted(
            (int(register), int(value) & 0xFFFFFFFF)
            for register, value in fixpoint.out_reg_maps.get(int(member.owner_serial), {}).items()
        )
    )
    out_stk, out_reg = _transfer_snapshot_constant_block(
        feeder,
        dict(actual_stack),
        dict(actual_registers),
        effective_stkoff,
    )
    actual = (
        out_reg.get(int(state_var_reg))
        if state_var_reg is not None
        else out_stk.get(int(state_var_stkoff))
    )
    return actual is not None and (int(actual) & 0xFFFFFFFF) == int(member.state_constant)


@dataclass(frozen=True, slots=True)
class SemanticRouteFact:
    """Immutable route facts emitted by state recovery, before identity binding."""

    kind: SemanticRouteFactKind
    owner_serial: int
    source_serial: int
    source_instruction_ea: int
    state_constant: int
    target_serial: int
    owner_anchor_ea: int | None
    target_anchor_ea: int | None
    path_serials: tuple[int, ...]
    path_edges: tuple[tuple[int, int], ...]
    fact_id: str | None = None
    transform_witness: ExactStateTransformFeeder | None = None
    carrier_witness: ExactCarrierStateWrite | None = None
    partition_witness: StatePartitionGroupWitness | None = None
    decision_dag_witness: "DecisionDagRouteWitness | None" = None
    bootstrap_witness: SemanticBootstrapRouteWitness | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SemanticRouteFactKind):
            raise TypeError("semantic route fact requires a typed kind")
        serials = tuple(int(serial) for serial in self.path_serials)
        bootstrap_path = (
            self.bootstrap_witness.corridor_serials[:-1]
            if self.kind is SemanticRouteFactKind.BOOTSTRAP
            and self.bootstrap_witness is not None
            else ()
        )
        if self.kind is SemanticRouteFactKind.BOOTSTRAP:
            valid_path = bool(serials) and serials == bootstrap_path and serials[0] == int(self.source_serial) and serials[-1] == int(self.owner_serial)
        else:
            valid_path = bool(serials) and serials[0] == int(self.owner_serial) and serials[-1] == int(self.source_serial)
        if not valid_path:
            raise SemanticRouteEvidenceRejected(
                "semantic route fact path must run from owner to physical source"
            )
        if len(set(serials)) != len(serials):
            raise SemanticRouteEvidenceRejected("semantic route fact path cannot repeat blocks")
        edges = tuple((int(source), int(target)) for source, target in self.path_edges)
        if len(edges) != len(serials) - 1 or tuple(source for source, _ in edges) != serials[:-1] or tuple(target for _, target in edges) != serials[1:]:
            raise SemanticRouteEvidenceRejected("semantic route fact path edges must be reciprocal")
        if int(self.owner_serial) < 0 or int(self.source_serial) < 0 or int(self.target_serial) < 0:
            raise SemanticRouteEvidenceRejected("semantic route fact serials must be non-negative")
        object.__setattr__(self, "owner_serial", int(self.owner_serial))
        object.__setattr__(self, "source_serial", int(self.source_serial))
        object.__setattr__(self, "source_instruction_ea", _native_ea(self.source_instruction_ea, "semantic route fact state-write"))
        if self.owner_anchor_ea is not None:
            object.__setattr__(self, "owner_anchor_ea", _native_ea(self.owner_anchor_ea, "semantic route fact owner"))
        if self.target_anchor_ea is not None:
            object.__setattr__(self, "target_anchor_ea", _native_ea(self.target_anchor_ea, "semantic route fact target"))
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)
        object.__setattr__(self, "target_serial", int(self.target_serial))
        object.__setattr__(self, "path_serials", serials)
        object.__setattr__(self, "path_edges", edges)
        if self.fact_id is not None:
            object.__setattr__(self, "fact_id", _identifier(self.fact_id, "semantic route fact id"))
        if self.kind is SemanticRouteFactKind.STATE_TRANSFORM:
            if not isinstance(self.transform_witness, ExactStateTransformFeeder):
                raise TypeError("state-transform route fact requires its typed witness")
            witness = self.transform_witness
            if (
                int(witness.source_serial) != int(self.owner_serial)
                or int(witness.state) != int(self.state_constant)
                or int(witness.source_ea) != int(self.source_instruction_ea)
            ):
                raise SemanticRouteEvidenceRejected(
                    "state-transform route fact does not match its witness"
                )
        elif self.transform_witness is not None:
            raise TypeError("only a state-transform fact may carry a transform witness")
        if self.kind is SemanticRouteFactKind.STATE_CARRIER:
            if not isinstance(self.carrier_witness, ExactCarrierStateWrite):
                raise TypeError("state-carrier route fact requires its typed witness")
            witness = self.carrier_witness
            if (
                int(witness.source_serial) != int(self.owner_serial)
                or int(witness.state) != int(self.state_constant)
            ):
                raise SemanticRouteEvidenceRejected(
                    "state-carrier route fact does not match its witness"
                )
        elif self.carrier_witness is not None:
            raise TypeError("only a state-carrier fact may carry a carrier witness")
        if self.kind is SemanticRouteFactKind.STATE_PARTITION:
            if not isinstance(self.partition_witness, StatePartitionGroupWitness):
                raise TypeError("state-partition route fact requires its group witness")
            member = tuple(
                item for item in self.partition_witness.members
                if int(item.owner_serial) == int(self.owner_serial)
            )
            if (
                len(member) != 1
                or int(self.source_serial) != int(self.partition_witness.feeder_serial)
                or int(member[0].state_constant) != int(self.state_constant)
            ):
                raise SemanticRouteEvidenceRejected("state-partition fact does not match group witness")
        elif self.partition_witness is not None:
            raise TypeError("only a state-partition fact may carry a partition witness")
        if self.kind is SemanticRouteFactKind.BOOTSTRAP:
            if not isinstance(self.bootstrap_witness, SemanticBootstrapRouteWitness):
                raise TypeError("bootstrap route fact requires its typed witness")
            witness = self.bootstrap_witness
            if (
                int(witness.owner_serial) != int(self.owner_serial)
                or int(witness.source_serial) != int(self.source_serial)
                or int(witness.source_instruction_ea) != int(self.source_instruction_ea)
                or int(witness.state_constant) != int(self.state_constant)
                or int(witness.dispatcher_serial) not in witness.corridor_serials
            ):
                raise SemanticRouteEvidenceRejected("bootstrap route fact does not match its witness")
        elif self.bootstrap_witness is not None:
            raise TypeError("only a bootstrap route fact may carry a bootstrap witness")
        if self.decision_dag_witness is not None and self.kind not in {
            SemanticRouteFactKind.DECISION_DAG,
            SemanticRouteFactKind.STATE_PARTITION,
            SemanticRouteFactKind.BOOTSTRAP,
        }:
            raise TypeError("only a decision-DAG fact may carry a DAG witness")


@dataclass(frozen=True, slots=True)
class CanonicalSemanticEvidenceProductionContext:
    """Immutable source snapshot and identity context for one evidence build."""

    native_key: NativePreanalysisKey
    generation: int
    atomic_group_id: str
    state_identity: StorageIdentity
    blocks: tuple[BlockSnapshot, ...]
    identities_by_serial: tuple[tuple[int, StableBlockIdentity], ...]
    entry_serial: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("canonical production context requires a native key")
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("canonical production context requires state identity")
        blocks = tuple(self.blocks)
        identities = tuple((int(serial), identity) for serial, identity in self.identities_by_serial)
        if any(not isinstance(block, BlockSnapshot) for block in blocks):
            raise TypeError("canonical production context requires block snapshots")
        if len({block.serial for block in blocks}) != len(blocks) or len({serial for serial, _ in identities}) != len(identities):
            raise SemanticRouteEvidenceRejected("canonical production context has duplicate serials")
        if any(identity.native_key != self.native_key for _, identity in identities):
            raise SemanticRouteEvidenceRejected("canonical production identity key mismatch")
        entry_serial = (
            int(blocks[0].serial)
            if self.entry_serial is None and blocks
            else None
            if self.entry_serial is None
            else int(self.entry_serial)
        )
        if entry_serial is not None and entry_serial not in {int(block.serial) for block in blocks}:
            raise SemanticRouteEvidenceRejected("canonical production entry is missing")
        object.__setattr__(self, "generation", int(self.generation))
        object.__setattr__(self, "atomic_group_id", _identifier(self.atomic_group_id, "canonical production atomic group"))
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(self, "identities_by_serial", identities)
        object.__setattr__(self, "entry_serial", entry_serial)

    def identity(self, serial: int) -> StableBlockIdentity | None:
        return dict(self.identities_by_serial).get(int(serial))

    def block(self, serial: int) -> BlockSnapshot | None:
        return next((block for block in self.blocks if block.serial == int(serial)), None)


class CanonicalRouteAssessmentPhase(str, Enum):
    """Lifecycle phase in which one canonical route was assessed."""

    SOURCE = "source"
    PROJECTED = "projected"
    OBSERVED = "observed"


class CanonicalRouteAssessmentRejection(str, Enum):
    """Typed reasons for an assessment that did not become authoritative."""

    ROUTE_BINDING_FAILED = "route_binding_failed"
    GRAPH_IDENTITY_MISMATCH = "graph_identity_mismatch"
    GENERATION_MISMATCH = "generation_mismatch"
    PREDICATE_NOT_LIVE = "predicate_not_live"


class CanonicalRouteBindingStage(str, Enum):
    """Exact stage at which one canonical proof failed source binding."""

    CANONICAL_IDENTITY = "canonical_identity"
    SOURCE_IDENTITY = "source_identity"
    DESTINATION_IDENTITY = "destination_identity"
    SUBPROOF_IDENTITY = "subproof_identity"
    STATE_WRITE = "state_write"
    STATE_WRITE_CORRIDOR = "state_write_corridor"
    STATE_TRANSFORM = "state_transform"
    STATE_CARRIER = "state_carrier"
    STATE_PARTITION = "state_partition"
    STATE_DAG = "state_dag"
    BOOTSTRAP = "bootstrap"
    CONDITIONAL_ROUTE = "conditional_route"
    DIRECT_ROUTE = "direct_route"
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
    authority_transfer_ea: int | None
    preserved_call_instruction_eas: tuple[int, ...]
    delivery_kind: SemanticStateWriteDeliveryKind = (
        SemanticStateWriteDeliveryKind.INDIRECT
    )

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
        if not isinstance(self.delivery_kind, SemanticStateWriteDeliveryKind):
            raise TypeError("semantic state write requires a typed delivery kind")
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
        authority_transfer_ea = (
            None
            if self.authority_transfer_ea is None
            else _native_ea(
                self.authority_transfer_ea,
                "semantic state-write authority transfer",
            )
        )
        preserved_call_instruction_eas = tuple(
            _native_ea(ea, "semantic state-write preserved call")
            for ea in self.preserved_call_instruction_eas
        )
        if (authority_transfer_ea is None) != (not preserved_call_instruction_eas):
            raise SemanticRouteEvidenceRejected(
                "semantic state-write call preservation requires one transfer authority"
            )
        if preserved_call_instruction_eas:
            if (
                preserved_call_instruction_eas
                != tuple(sorted(set(preserved_call_instruction_eas)))
                or not set(preserved_call_instruction_eas).issubset(corridor)
                or any(
                    not instruction_ea < call_ea < corridor[-1]
                    for call_ea in preserved_call_instruction_eas
                )
                or authority_transfer_ea is None
                or not corridor[-1] < authority_transfer_ea
            ):
                raise SemanticRouteEvidenceRejected(
                    "semantic state-write preserved calls require an ordered "
                    "write-to-delivery corridor before their transfer authority"
                )
        object.__setattr__(self, "instruction_ea", instruction_ea)
        object.__setattr__(self, "width", width)
        object.__setattr__(self, "state_constant", int(self.state_constant))
        object.__setattr__(self, "corridor_instruction_eas", corridor)
        object.__setattr__(self, "authority_transfer_ea", authority_transfer_ea)
        object.__setattr__(
            self,
            "preserved_call_instruction_eas",
            preserved_call_instruction_eas,
        )


@dataclass(frozen=True, slots=True)
class DecisionDagRouteWitness:
    """Source-snapshot route witness emitted by the exact DAG resolver."""

    state_identity: StorageIdentity
    state_constant: int
    entry_serial: int
    entry_anchor_ea: int
    path_serials: tuple[int, ...]
    path_anchors: tuple[int, ...]
    comparisons: tuple[tuple[int, RouteComparison], ...]
    aliases: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("decision-DAG witness requires state identity")
        serials = tuple(int(item) for item in self.path_serials)
        anchors = tuple(int(item) for item in self.path_anchors)
        if not serials or serials[0] != int(self.entry_serial) or len(serials) != len(anchors):
            raise SemanticRouteEvidenceRejected("decision-DAG path must begin at entry")
        if any(not isinstance(item, RouteComparison) for _, item in self.comparisons):
            raise TypeError("decision-DAG witness requires typed comparisons")
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)
        object.__setattr__(self, "entry_serial", int(self.entry_serial))
        object.__setattr__(self, "path_serials", serials)
        object.__setattr__(self, "path_anchors", anchors)
        object.__setattr__(self, "comparisons", tuple(self.comparisons))
        object.__setattr__(self, "aliases", tuple((int(a), int(b)) for a, b in self.aliases))


@dataclass(frozen=True, slots=True)
class SemanticDagComparison:
    """Stable comparison node and both exact successor identities."""

    node: SemanticCorridorPoint
    operation: str
    constant: int
    true_target: SemanticCorridorPoint
    false_target: SemanticCorridorPoint

    def __post_init__(self) -> None:
        if not all(
            isinstance(point, SemanticCorridorPoint)
            for point in (self.node, self.true_target, self.false_target)
        ):
            raise TypeError("DAG comparison requires stable corridor points")
        if type(self.operation) is not str or not self.operation:
            raise SemanticRouteEvidenceRejected("DAG comparison requires an operation")
        object.__setattr__(self, "constant", int(self.constant) & 0xFFFFFFFF)


@dataclass(frozen=True, slots=True)
class SemanticDecisionDagWitness:
    """Canonical DAG witness in stable identity/anchor coordinates."""

    state_identity: StorageIdentity
    state_constant: int
    entry: SemanticCorridorPoint
    path: tuple[SemanticCorridorPoint, ...]
    comparisons: tuple[SemanticDagComparison, ...]
    aliases: tuple[tuple[SemanticCorridorPoint, SemanticCorridorPoint], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("decision-DAG witness requires state identity")
        if not isinstance(self.entry, SemanticCorridorPoint):
            raise TypeError("decision-DAG witness requires stable entry")
        path = tuple(self.path)
        if not path or path[0] != self.entry:
            raise SemanticRouteEvidenceRejected("decision-DAG path must begin at entry")
        if any(not isinstance(item, SemanticDagComparison) for item in self.comparisons):
            raise TypeError("decision-DAG witness requires stable comparisons")
        aliases = tuple(self.aliases)
        if any(
            len(item) != 2
            or not isinstance(item[0], SemanticCorridorPoint)
            or not isinstance(item[1], SemanticCorridorPoint)
            for item in aliases
        ):
            raise TypeError("decision-DAG witness requires stable aliases")
        alias_sources = [item[0].identity for item in aliases]
        if len(set(alias_sources)) != len(alias_sources):
            raise SemanticRouteEvidenceRejected("decision-DAG aliases have duplicate sources")
        comparison_nodes = [item.node.identity for item in self.comparisons]
        if len(set(comparison_nodes)) != len(comparison_nodes):
            raise SemanticRouteEvidenceRejected("decision-DAG comparisons have duplicate nodes")
        if set(alias_sources) & set(comparison_nodes):
            raise SemanticRouteEvidenceRejected("decision-DAG alias/comparison ownership overlaps")
        alias_targets = {source: target for source, target in aliases}
        if len(alias_targets) != len(aliases):
            raise SemanticRouteEvidenceRejected("decision-DAG aliases have conflicting targets")
        for source in alias_targets:
            seen: set[SemanticCorridorPoint] = set()
            current = source
            while current in alias_targets:
                if current in seen:
                    raise SemanticRouteEvidenceRejected("decision-DAG aliases contain a cycle")
                seen.add(current)
                current = alias_targets[current]
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "comparisons", tuple(self.comparisons))
        object.__setattr__(self, "aliases", aliases)


@dataclass(frozen=True, slots=True)
class SemanticStateDagProof:
    """Canonical proof for a route resolved by an exact comparison DAG."""

    witness: SemanticDecisionDagWitness
    source_identity: StableBlockIdentity
    source_anchor_ea: int
    target_identity: StableBlockIdentity
    target_anchor_ea: int
    entry_identity: StableBlockIdentity
    entry_anchor_ea: int
    path: tuple[SemanticCorridorPoint, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.witness, SemanticDecisionDagWitness):
            raise TypeError("state-DAG proof requires its typed witness")
        if not isinstance(self.source_identity, StableBlockIdentity):
            raise TypeError("state-DAG proof requires source identity")
        if not isinstance(self.target_identity, StableBlockIdentity):
            raise TypeError("state-DAG proof requires target identity")
        if not isinstance(self.entry_identity, StableBlockIdentity):
            raise TypeError("state-DAG proof requires entry identity")
        if not self.source_identity.native_ranges.contains(int(self.source_anchor_ea)):
            raise SemanticRouteEvidenceRejected("state-DAG source anchor is outside identity")
        if not self.target_identity.native_ranges.contains(int(self.target_anchor_ea)):
            raise SemanticRouteEvidenceRejected("state-DAG target anchor is outside identity")
        if not self.entry_identity.native_ranges.contains(int(self.entry_anchor_ea)):
            raise SemanticRouteEvidenceRejected("state-DAG entry anchor is outside identity")
        points = tuple(self.path)
        if (
            not points
            or points[0].identity != self.entry_identity
            or points[0].anchor_ea != int(self.entry_anchor_ea)
        ):
            raise SemanticRouteEvidenceRejected("state-DAG path is empty")
        if points != tuple(self.witness.path):
            raise SemanticRouteEvidenceRejected("state-DAG path length drift")


@dataclass(frozen=True, slots=True)
class SemanticBootstrapProof:
    """Stable bootstrap entry witness, including its preserved corridor effects."""

    entry: SemanticCorridorPoint
    source: SemanticCorridorPoint
    owner: SemanticCorridorPoint
    dispatcher: SemanticCorridorPoint
    corridor: tuple[SemanticCorridorPoint, ...]
    state_write: SemanticStateWriteProof
    state_dag: SemanticStateDagProof
    preserved_effect_sites: tuple[InstructionEffectSite, ...]

    def __post_init__(self) -> None:
        points = tuple(self.corridor)
        if any(not isinstance(point, SemanticCorridorPoint) for point in points):
            raise TypeError("bootstrap proof requires stable corridor points")
        if (
            not points
            or points[0] != self.source
            or points[-1] != self.dispatcher
            or len(set(points)) != len(points)
            or self.owner not in points
            or self.entry.native_key != self.source.native_key
            or any(point.native_key != self.source.native_key for point in points)
        ):
            raise SemanticRouteEvidenceRejected("bootstrap stable corridor is incomplete")
        if (
            not isinstance(self.state_write, SemanticStateWriteProof)
            or self.state_write.identity != self.source.identity
            or self.state_write.instruction_ea != self.source.anchor_ea
            or self.state_write.width != 4
            or not isinstance(self.state_dag, SemanticStateDagProof)
        ):
            raise SemanticRouteEvidenceRejected("bootstrap proof requires exact write and DAG")
        effects = tuple(self.preserved_effect_sites)
        if any(not isinstance(site, InstructionEffectSite) for site in effects):
            raise TypeError("bootstrap preserved effects require typed effect sites")
        if effects != tuple(sorted(effects, key=lambda site: (site.instruction_ea, site.host_instruction_ea, site.kind.value))):
            raise SemanticRouteEvidenceRejected("bootstrap preserved effects must be ordered")
        object.__setattr__(self, "corridor", points)
        object.__setattr__(self, "preserved_effect_sites", effects)


@dataclass(frozen=True, slots=True)
class SemanticStateCarrierProof:
    """Stable, source-bound proof for a CONST32 carrier corridor."""

    carrier: Varnode
    owner_identity: StableBlockIdentity
    owner_anchor_ea: int
    source_identity: StableBlockIdentity
    source_anchor_ea: int
    feeder_identity: StableBlockIdentity
    feeder_anchor_ea: int
    comparison_entry_identity: StableBlockIdentity
    comparison_entry_anchor_ea: int
    state_identity: StorageIdentity
    state_constant: int
    requires_feeder_clone: bool
    corridor: tuple[SemanticCorridorPoint, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.carrier, Varnode):
            raise TypeError("state-carrier proof requires a typed carrier")
        identities = (
            self.owner_identity, self.source_identity,
            self.feeder_identity, self.comparison_entry_identity,
        )
        if any(not isinstance(identity, StableBlockIdentity) for identity in identities):
            raise TypeError("state-carrier proof requires stable identities")
        for identity, anchor in (
            (self.owner_identity, self.owner_anchor_ea),
            (self.source_identity, self.source_anchor_ea),
            (self.feeder_identity, self.feeder_anchor_ea),
            (self.comparison_entry_identity, self.comparison_entry_anchor_ea),
        ):
            normalized = _native_ea(anchor, "state-carrier block anchor")
            if not identity.native_ranges.contains(normalized):
                raise SemanticRouteEvidenceRejected(
                    "state-carrier block anchor is outside its identity"
                )
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("state-carrier proof requires state identity")
        points = tuple(self.corridor)
        expected = (
            SemanticCorridorPoint(self.source_identity, self.source_anchor_ea),
            SemanticCorridorPoint(self.feeder_identity, self.feeder_anchor_ea),
            SemanticCorridorPoint(
                self.comparison_entry_identity,
                self.comparison_entry_anchor_ea,
            ),
        )
        if points != expected:
            raise SemanticRouteEvidenceRejected(
                "state-carrier proof corridor does not match its identities"
            )
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)
        object.__setattr__(self, "corridor", points)


@dataclass(frozen=True, slots=True)
class SemanticPartitionMemberProof:
    owner_identity: StableBlockIdentity
    owner_anchor_ea: int
    state_constant: int


@dataclass(frozen=True, slots=True)
class SemanticStatePartitionProof:
    """Stable group certificate for predecessor-specific state production."""

    group_id: str
    feeder_identity: StableBlockIdentity
    feeder_anchor_ea: int
    feeder_instruction_ea: int
    state_identity: StorageIdentity
    members: tuple[SemanticPartitionMemberProof, ...]

    def __post_init__(self) -> None:
        members = tuple(self.members)
        if not members or any(not isinstance(item, SemanticPartitionMemberProof) for item in members):
            raise SemanticRouteEvidenceRejected("state partition requires members")
        owners = tuple(item.owner_identity for item in members)
        if len(set(owners)) != len(owners):
            raise SemanticRouteEvidenceRejected("state partition has duplicate owners")
        if not self.feeder_identity.native_ranges.contains(int(self.feeder_anchor_ea)):
            raise SemanticRouteEvidenceRejected("state partition feeder anchor is outside identity")
        if not self.feeder_identity.native_ranges.contains(int(self.feeder_instruction_ea)):
            raise SemanticRouteEvidenceRejected("state partition write is outside feeder identity")
        expected_group_id = _canonical_partition_group_id(
            self.feeder_identity,
            int(self.feeder_instruction_ea),
            self.state_identity,
            members,
        )
        if self.group_id != expected_group_id:
            raise SemanticRouteEvidenceRejected(
                "state partition group id does not match canonical content"
            )
        object.__setattr__(self, "group_id", expected_group_id)
        object.__setattr__(self, "members", members)
        object.__setattr__(self, "feeder_instruction_ea", _native_ea(self.feeder_instruction_ea, "state partition write"))


def _canonical_partition_group_id(
    feeder: StableBlockIdentity,
    feeder_instruction_ea: int,
    state_identity: StorageIdentity,
    members: tuple[SemanticPartitionMemberProof, ...],
) -> str:
    def stable_identity_payload(identity: StableBlockIdentity) -> dict[str, object]:
        return {
            "native_key": identity.native_key.to_dict(),
            "exact_instruction_eas": sorted(int(ea) for ea in identity.exact_instruction_eas),
            "native_ranges": [
                [int(interval.start_ea), int(interval.end_ea)]
                for interval in identity.native_ranges.intervals
            ],
        }

    def stable_identity_sort_key(identity: StableBlockIdentity) -> str:
        return json.dumps(
            stable_identity_payload(identity), sort_keys=True, separators=(",", ":")
        )

    if not isinstance(state_identity, StorageIdentity):
        raise TypeError("partition group id requires state identity")
    payload = {
        "feeder": stable_identity_payload(feeder),
        "feeder_instruction_ea": int(feeder_instruction_ea),
        "state_identity": {
            "kind": state_identity.kind.value,
            "offset": int(state_identity.offset),
        },
        "members": tuple(
            (
                stable_identity_payload(member.owner_identity),
                int(member.owner_anchor_ea),
                int(member.state_constant),
            )
            for member in sorted(members, key=lambda item: stable_identity_sort_key(item.owner_identity))
        ),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "partition-group:sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _canonical_partition_proof_id(
    group_id: str,
    owner: StableBlockIdentity,
    target: StableBlockIdentity,
    state_identity: StorageIdentity,
    state_constant: int,
) -> str:
    """Derive a partition member ID without snapshot-local serials."""
    payload = {
        "group_id": str(group_id),
        "owner": owner.to_dict(),
        "target": target.to_dict(),
        "state_identity": {
            "kind": state_identity.kind.value,
            "offset": int(state_identity.offset),
        },
        "state_constant": int(state_constant) & 0xFFFFFFFF,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "partition-proof:sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SemanticStateTransformProof:
    """Exact bounded state-transform witness in stable native coordinates.

    ``witness`` is the same typed state-carrier proof produced by recovery and
    replayed by binding.  The identity/anchor rows make its owner, source,
    feeder, comparison entry, and optional state feeder explicit to the
    canonical route contract without turning the legacy transition receipt
    into authority.
    """

    operation: ValueOpKind
    program: tuple[Instruction, ...]
    source_bindings: tuple[tuple[Varnode, int], ...]
    owner_identity: StableBlockIdentity
    owner_anchor_ea: int
    source_identity: StableBlockIdentity
    source_anchor_ea: int
    feeder_identity: StableBlockIdentity
    feeder_anchor_ea: int
    comparison_entry_identity: StableBlockIdentity
    comparison_entry_anchor_ea: int
    state_feeder_identity: StableBlockIdentity | None
    state_feeder_anchor_ea: int | None
    state_identity: StorageIdentity
    state_constant: int
    corridor: tuple[SemanticCorridorPoint, ...]
    corridor_instruction_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.operation, ValueOpKind):
            raise TypeError("state-transform proof requires a typed operation")
        if any(not isinstance(instruction, Instruction) for instruction in self.program):
            raise TypeError("state-transform proof requires typed program instructions")
        if any(
            not isinstance(binding, tuple)
            or len(binding) != 2
            or not isinstance(binding[0], Varnode)
            or type(binding[1]) is not int
            for binding in self.source_bindings
        ):
            raise TypeError("state-transform proof requires typed source bindings")
        identities = (
            self.owner_identity,
            self.source_identity,
            self.feeder_identity,
            self.comparison_entry_identity,
        )
        if any(not isinstance(identity, StableBlockIdentity) for identity in identities):
            raise TypeError("state-transform proof requires stable identities")
        if self.state_feeder_identity is not None and not isinstance(
            self.state_feeder_identity, StableBlockIdentity
        ):
            raise TypeError("state-transform state feeder requires stable identity")
        anchors = (
            (self.owner_identity, self.owner_anchor_ea),
            (self.source_identity, self.source_anchor_ea),
            (self.feeder_identity, self.feeder_anchor_ea),
            (self.comparison_entry_identity, self.comparison_entry_anchor_ea),
        )
        if self.state_feeder_identity is not None:
            if self.state_feeder_anchor_ea is None:
                raise SemanticRouteEvidenceRejected(
                    "state-transform state feeder requires an anchor"
                )
            anchors += ((self.state_feeder_identity, self.state_feeder_anchor_ea),)
        elif self.state_feeder_anchor_ea is not None:
            raise SemanticRouteEvidenceRejected(
                "state-transform state feeder anchor requires an identity"
            )
        for identity, anchor in anchors:
            normalized = _native_ea(anchor, "state-transform block anchor")
            if not identity.native_ranges.contains(normalized):
                raise SemanticRouteEvidenceRejected(
                    "state-transform block anchor is outside its identity"
                )
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("state-transform proof requires state identity")
        corridor_points = tuple(self.corridor)
        if not corridor_points or any(not isinstance(point, SemanticCorridorPoint) for point in corridor_points):
            raise SemanticRouteEvidenceRejected(
                "state-transform proof requires an exact path"
            )
        expected_points = (
            SemanticCorridorPoint(self.source_identity, self.source_anchor_ea),
            SemanticCorridorPoint(self.feeder_identity, self.feeder_anchor_ea),
            *(
                (SemanticCorridorPoint(self.state_feeder_identity, self.state_feeder_anchor_ea),)
                if self.state_feeder_identity is not None
                else ()
            ),
            SemanticCorridorPoint(
                self.comparison_entry_identity,
                self.comparison_entry_anchor_ea,
            ),
        )
        if corridor_points != expected_points or self.owner_identity != self.source_identity:
            raise SemanticRouteEvidenceRejected(
                "state-transform proof corridor does not match its identities"
            )
        corridor_eas = tuple(_native_ea(ea, "state-transform corridor instruction") for ea in self.corridor_instruction_eas)
        if not corridor_eas or corridor_eas != tuple(sorted(set(corridor_eas))):
            raise SemanticRouteEvidenceRejected(
                "state-transform proof corridor must be ordered and exact"
            )
        object.__setattr__(self, "owner_anchor_ea", _native_ea(self.owner_anchor_ea, "state-transform owner anchor"))
        object.__setattr__(self, "source_anchor_ea", _native_ea(self.source_anchor_ea, "state-transform source anchor"))
        object.__setattr__(self, "feeder_anchor_ea", _native_ea(self.feeder_anchor_ea, "state-transform feeder anchor"))
        object.__setattr__(self, "comparison_entry_anchor_ea", _native_ea(self.comparison_entry_anchor_ea, "state-transform comparison anchor"))
        if self.state_feeder_anchor_ea is not None:
            object.__setattr__(self, "state_feeder_anchor_ea", _native_ea(self.state_feeder_anchor_ea, "state-transform feeder anchor"))
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)
        object.__setattr__(self, "program", tuple(self.program))
        object.__setattr__(self, "source_bindings", tuple(self.source_bindings))
        object.__setattr__(self, "corridor", corridor_points)
        object.__setattr__(self, "corridor_instruction_eas", corridor_eas)


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
    delivery_region: NativeEaInterval | None = None
    source_owner_identity: StableBlockIdentity | None = None
    source_owner_anchor_ea: int | None = None
    state_write: SemanticStateWriteProof | None = None
    state_transform: SemanticStateTransformProof | None = None
    state_carrier: SemanticStateCarrierProof | None = None
    state_partition: SemanticStatePartitionProof | None = None
    state_dag: SemanticStateDagProof | None = None
    bootstrap: SemanticBootstrapProof | None = None
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

        delivery_region = self.delivery_region
        if self.shape is SemanticRouteShape.DIRECT:
            if not isinstance(delivery_region, NativeEaInterval):
                raise SemanticRouteEvidenceRejected(
                    "direct semantic route requires an exact delivery region"
                )
            if not (
                delivery_region.start_ea <= source_anchor_ea < delivery_region.end_ea
            ):
                raise SemanticRouteEvidenceRejected(
                    "direct semantic route anchor is outside its delivery region"
                )
        elif delivery_region is not None:
            raise SemanticRouteEvidenceRejected(
                "conditional semantic route cannot claim a direct delivery region"
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
            if predicate.consumer.identity != source_point.identity:
                raise SemanticRouteEvidenceRejected(
                    "conditional predicate consumer must be in the route source block"
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
                if not any(
                    consumer.identity == source_point.identity
                    for consumer in carrier.consumers
                ):
                    raise SemanticRouteEvidenceRejected(
                        "storage predicate carrier must reach the route source block"
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
            authority_transfer_ea = state_write.authority_transfer_ea
            if authority_transfer_ea is not None and (
                self.shape is not SemanticRouteShape.DIRECT
                or delivery_region is None
                or state_write.corridor_instruction_eas[-1] != source_anchor_ea
                or not delivery_region.start_ea
                <= authority_transfer_ea
                < delivery_region.end_ea
            ):
                raise SemanticRouteEvidenceRejected(
                    "semantic state-write transfer authority must belong to its "
                    "direct delivery region"
                )
        state_transform = self.state_transform
        if state_transform is not None:
            if not isinstance(state_transform, SemanticStateTransformProof):
                raise TypeError("semantic route state transform has the wrong type")
            if any(
                identity.native_key != native_key
                for identity in (
                    state_transform.owner_identity,
                    state_transform.source_identity,
                    state_transform.feeder_identity,
                    state_transform.comparison_entry_identity,
                    state_transform.state_feeder_identity,
                )
                if identity is not None
            ):
                raise SemanticRouteEvidenceRejected(
                    "semantic route state transform belongs to another native key"
                )
        state_carrier = self.state_carrier
        if state_carrier is not None:
            if not isinstance(state_carrier, SemanticStateCarrierProof):
                raise TypeError("semantic route state carrier has the wrong type")
            if any(
                identity.native_key != native_key
                for identity in (
                    state_carrier.owner_identity,
                    state_carrier.source_identity,
                    state_carrier.feeder_identity,
                    state_carrier.comparison_entry_identity,
                )
            ):
                raise SemanticRouteEvidenceRejected(
                    "semantic route state carrier belongs to another native key"
                )
        state_partition = self.state_partition
        if state_partition is not None:
            if not isinstance(state_partition, SemanticStatePartitionProof):
                raise TypeError("semantic route state partition has the wrong type")
            if state_partition.feeder_identity.native_key != native_key:
                raise SemanticRouteEvidenceRejected("semantic route state partition belongs to another native key")
            if any(item.owner_identity.native_key != native_key for item in state_partition.members):
                raise SemanticRouteEvidenceRejected("semantic route partition owner belongs to another native key")
        state_dag = self.state_dag
        if state_dag is not None:
            if not isinstance(state_dag, SemanticStateDagProof):
                raise TypeError("semantic route state DAG has the wrong type")
            if (
                state_dag.source_identity.native_key != native_key
                or state_dag.target_identity.native_key != native_key
                or state_dag.entry_identity.native_key != native_key
            ):
                raise SemanticRouteEvidenceRejected(
                    "semantic route state DAG belongs to another native key"
                )
        bootstrap = self.bootstrap
        if self.proof_kind is not SemanticRouteProofKind.BOOTSTRAP and bootstrap is not None:
            raise SemanticRouteEvidenceRejected(
                "only a bootstrap route may carry bootstrap evidence"
            )
        if self.proof_kind is SemanticRouteProofKind.STATE_TRANSFORM:
            if (
                self.shape is not SemanticRouteShape.DIRECT
                or state_transform is None
                or state_carrier is not None
                or state_write is not None
                or len(destinations) != 1
                or self.source_identity != state_transform.source_identity
                or self.source_anchor_ea != state_transform.source_anchor_ea
                or destinations[0].state_constant != state_transform.state_constant
            ):
                raise SemanticRouteEvidenceRejected(
                    "state transform requires its exact bounded witness"
                )
        elif self.proof_kind is SemanticRouteProofKind.STATE_CARRIER:
            if (
                self.shape is not SemanticRouteShape.DIRECT
                or state_carrier is None
                or state_transform is not None
                or state_write is not None
                or len(destinations) != 1
                or self.source_identity != state_carrier.source_identity
                or self.source_anchor_ea != state_carrier.source_anchor_ea
                or destinations[0].state_constant != state_carrier.state_constant
            ):
                raise SemanticRouteEvidenceRejected(
                    "state carrier requires its exact bounded witness"
                )
        elif self.proof_kind is SemanticRouteProofKind.STATE_PARTITION:
            member = (
                None
                if state_partition is None
                else next((item for item in state_partition.members if item.owner_identity == self.source_owner_identity), None)
            )
            if (
                self.shape is not SemanticRouteShape.DIRECT
                or state_partition is None
                or state_transform is not None
                or state_carrier is not None
                or state_write is not None
                or state_dag is None
                or self.source_owner_identity is None
                or member is None
                or len(destinations) != 1
                or self.source_identity != state_partition.feeder_identity
                or self.source_anchor_ea != state_partition.feeder_instruction_ea
                or destinations[0].state_constant != member.state_constant
                or self.source_identity != state_dag.source_identity
                or destinations[0].target_identity != state_dag.target_identity
                or destinations[0].target_anchor_ea != state_dag.target_anchor_ea
                or state_partition.state_identity != state_dag.witness.state_identity
                or member.state_constant != state_dag.witness.state_constant
                or destinations[0].state_constant != state_dag.witness.state_constant
            ):
                raise SemanticRouteEvidenceRejected("state partition requires its exact group witness")
        elif self.proof_kind is SemanticRouteProofKind.STATE_DAG:
            if (
                self.shape is not SemanticRouteShape.DIRECT
                or state_dag is None
                or state_transform is not None
                or state_carrier is not None
                or state_write is None
                or len(destinations) != 1
                or self.source_identity != state_dag.source_identity
                or self.source_anchor_ea != state_dag.source_anchor_ea
                or state_write.identity != self.source_identity
                or state_write.instruction_ea != self.source_anchor_ea
                or state_write.state_variable != state_dag.witness.state_identity
                or state_write.state_constant != state_dag.witness.state_constant
                or state_write.state_constant != destinations[0].state_constant
                or state_write.width != 4
                or destinations[0].target_identity != state_dag.target_identity
                or destinations[0].target_anchor_ea != state_dag.target_anchor_ea
                or destinations[0].state_constant != state_dag.witness.state_constant
            ):
                raise SemanticRouteEvidenceRejected(
                    "state DAG requires its exact typed witness"
                )
        elif self.proof_kind is SemanticRouteProofKind.BOOTSTRAP:
            if (
                self.shape is not SemanticRouteShape.DIRECT
                or not isinstance(self.bootstrap, SemanticBootstrapProof)
                or state_write is None
                or state_dag is None
                or len(destinations) != 1
                or self.source_identity != self.bootstrap.owner.identity
                or self.source_anchor_ea != self.bootstrap.owner.anchor_ea
                or state_write != self.bootstrap.state_write
                or state_dag != self.bootstrap.state_dag
                or destinations[0].state_constant != state_write.state_constant
                or destinations[0].target_identity != state_dag.target_identity
                or destinations[0].target_anchor_ea != state_dag.target_anchor_ea
            ):
                raise SemanticRouteEvidenceRejected(
                    "bootstrap route requires its exact entry, corridor, write, and DAG witness"
                )
        else:
            if state_transform is not None:
                raise SemanticRouteEvidenceRejected(
                    "only a state-transform route may carry transform evidence"
                )
            if state_carrier is not None:
                raise SemanticRouteEvidenceRejected(
                    "only a state-carrier route may carry carrier evidence"
                )
            if state_dag is not None:
                raise SemanticRouteEvidenceRejected(
                    "only a state-DAG route may carry DAG evidence"
                )
            if state_partition is not None:
                raise SemanticRouteEvidenceRejected("only a state-partition route may carry partition evidence")
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


def semantic_route_proof_reaches_consumer(
    proof: SemanticRouteProof,
    consumer: SemanticRouteProof,
) -> bool:
    """Match one destination to a consumer through an exact shared anchor."""
    source_anchor_ea = int(consumer.source_anchor_ea)
    source_identity = consumer.source_identity
    if source_anchor_ea not in source_identity.exact_instruction_eas:
        return False
    return any(
        int(destination.target_anchor_ea) == source_anchor_ea
        and stable_block_identities_refine_at_anchor(
            source_identity,
            destination.target_identity,
            source_anchor_ea,
        )
        for destination in proof.destinations
    )


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
        if generation < 0:
            raise SemanticRouteEvidenceRejected(
                "canonical semantic evidence generation must be non-negative"
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
        _validate_content_derived_ids(
            native_key=self.native_key,
            generation=generation,
            atomic_group_id=atomic_group_id,
            route_proofs=route_proofs,
        )
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "atomic_group_id", atomic_group_id)
        object.__setattr__(
            self,
            "route_proofs",
            tuple(sorted(route_proofs, key=lambda proof: proof.proof_id)),
        )


class CanonicalSemanticEvidenceProductionStage(str, Enum):
    """Closed producer stage at which a proposal was declined."""

    CONTEXT = "context"
    GROUP = "group"
    FACT = "fact"
    CANONICAL_MODEL = "canonical_model"


class CanonicalSemanticEvidenceProductionReason(str, Enum):
    """Stable, exhaustively testable producer-abstention codes."""

    EMPTY_GROUP = "empty_group"
    NEGATIVE_GENERATION = "negative_generation"
    PARTITION_GROUP_INCOMPLETE = "partition_group_incomplete"
    PARTITION_MISSING_WITNESS = "partition_missing_witness"
    PARTITION_IDENTITY_MISSING = "partition_identity_missing"
    PARTITION_ANCHOR_MISSING = "partition_anchor_missing"
    PARTITION_DELIVERY_REGION_MISSING = "partition_delivery_region_missing"
    PARTITION_MISSING_DECISION_DAG = "partition_missing_decision_dag"
    PARTITION_DAG_PATH_SHAPE = "partition_dag_path_shape"
    PARTITION_DAG_PATH_ANCHOR = "partition_dag_path_anchor"
    PARTITION_DAG_ENTRY_ANCHOR = "partition_dag_entry_anchor"
    PARTITION_DAG_COMPARISON_IDENTITY = "partition_dag_comparison_identity"
    PARTITION_DAG_ALIAS_IDENTITY = "partition_dag_alias_identity"
    CARRIER_MISSING_WITNESS = "carrier_missing_witness"
    CARRIER_FACT_IDENTITY_MISMATCH = "carrier_fact_identity_mismatch"
    CARRIER_IDENTITY_MISSING = "carrier_identity_missing"
    CARRIER_SOURCE_ANCHOR_MISSING = "carrier_source_anchor_missing"
    CARRIER_SOURCE_INSTRUCTION_MISSING = "carrier_source_instruction_missing"
    CARRIER_ANCHOR_MISSING = "carrier_anchor_missing"
    CARRIER_TARGET_ANCHOR_MISSING = "carrier_target_anchor_missing"
    CARRIER_SOURCE_RANGE_MISSING = "carrier_source_range_missing"
    DECISION_DAG_PATH_SHAPE = "decision_dag_path_shape"
    DECISION_DAG_PATH_ANCHOR = "decision_dag_path_anchor"
    DECISION_DAG_ENTRY_ANCHOR = "decision_dag_entry_anchor"
    DECISION_DAG_COMPARISON_IDENTITY = "decision_dag_comparison_identity"
    DECISION_DAG_ALIAS_IDENTITY = "decision_dag_alias_identity"
    DECISION_DAG_IDENTITY_MISSING = "decision_dag_identity_missing"
    DECISION_DAG_ROUTE_ANCHOR_MISSING = "decision_dag_route_anchor_missing"
    DECISION_DAG_SOURCE_RANGE_MISSING = "decision_dag_source_range_missing"
    DECISION_DAG_ALIAS_DUPLICATE_SOURCE = "decision_dag_alias_duplicate_source"
    DECISION_DAG_COMPARISON_DUPLICATE_NODE = "decision_dag_comparison_duplicate_node"
    DECISION_DAG_ALIAS_COMPARISON_OVERLAP = "decision_dag_alias_comparison_overlap"
    DECISION_DAG_ALIAS_CONFLICTING_TARGET = "decision_dag_alias_conflicting_target"
    DECISION_DAG_ALIAS_CYCLE = "decision_dag_alias_cycle"
    DECISION_DAG_STATE_IDENTITY_MISMATCH = "decision_dag_state_identity_mismatch"
    TRANSFORM_MISSING_WITNESS = "transform_missing_witness"
    TRANSFORM_FACT_IDENTITY_MISMATCH = "transform_fact_identity_mismatch"
    TRANSFORM_IDENTITY_MISSING = "transform_identity_missing"
    TRANSFORM_STATE_FEEDER_MISSING = "transform_state_feeder_missing"
    TRANSFORM_STATE_FEEDER_ANCHOR_MISSING = "transform_state_feeder_anchor_missing"
    TRANSFORM_ANCHOR_MISSING = "transform_anchor_missing"
    TRANSFORM_TARGET_ANCHOR_MISSING = "transform_target_anchor_missing"
    TRANSFORM_SOURCE_RANGE_MISSING = "transform_source_range_missing"
    ASSIGNMENT_IDENTITY_MISSING = "assignment_identity_missing"
    ASSIGNMENT_ANCHOR_SET_MISSING = "assignment_anchor_set_missing"
    ASSIGNMENT_ANCHOR_MISSING = "assignment_anchor_missing"
    ASSIGNMENT_SOURCE_RANGE_MISSING = "assignment_source_range_missing"
    ASSIGNMENT_SOURCE_ANCHOR_MISSING = "assignment_source_anchor_missing"
    ASSIGNMENT_DELIVERY_RANGE_MISSING = "assignment_delivery_range_missing"
    BOOTSTRAP_IDENTITY_MISSING = "bootstrap_identity_missing"
    BOOTSTRAP_CORRIDOR_INVALID = "bootstrap_corridor_invalid"
    BOOTSTRAP_STATE_WRITE_INVALID = "bootstrap_state_write_invalid"
    BOOTSTRAP_OWNER_RANGE_MISSING = "bootstrap_owner_range_missing"
    BOOTSTRAP_DAG_INVALID = "bootstrap_dag_invalid"
    BOOTSTRAP_SUBMODEL_REJECTED = "bootstrap_submodel_rejected"
    BOOTSTRAP_EFFECTS_INVALID = "bootstrap_effects_invalid"
    CANONICAL_MODEL_REJECTED = "canonical_model_rejected"


@dataclass(frozen=True, slots=True)
class CanonicalSemanticEvidenceProductionFactCoordinate:
    """Typed coordinates identifying the fact that caused abstention."""

    fact_kind: SemanticRouteFactKind
    owner_serial: int
    source_serial: int
    source_instruction_ea: int
    target_serial: int
    state_constant: int

    def __post_init__(self) -> None:
        if not isinstance(self.fact_kind, SemanticRouteFactKind):
            raise TypeError("production fact coordinate requires a typed fact kind")
        object.__setattr__(self, "owner_serial", int(self.owner_serial))
        object.__setattr__(self, "source_serial", int(self.source_serial))
        object.__setattr__(self, "source_instruction_ea", int(self.source_instruction_ea))
        object.__setattr__(self, "target_serial", int(self.target_serial))
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)


@dataclass(frozen=True, slots=True)
class CanonicalSemanticEvidenceProductionAbstention:
    """Typed producer abstention; reason and stage are authoritative."""

    reason: CanonicalSemanticEvidenceProductionReason
    stage: CanonicalSemanticEvidenceProductionStage
    coordinate: CanonicalSemanticEvidenceProductionFactCoordinate | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, CanonicalSemanticEvidenceProductionReason):
            raise TypeError("production abstention requires a typed reason")
        if not isinstance(self.stage, CanonicalSemanticEvidenceProductionStage):
            raise TypeError("production abstention requires a typed stage")
        if self.coordinate is not None and not isinstance(
            self.coordinate, CanonicalSemanticEvidenceProductionFactCoordinate
        ):
            raise TypeError("production abstention coordinate must be typed")
        if self.detail is not None and type(self.detail) is not str:
            raise TypeError("production abstention detail must be a string")


@dataclass(frozen=True, slots=True)
class CanonicalSemanticEvidenceProductionResult:
    """Exactly one accepted canonical evidence value or typed abstention."""

    evidence: CanonicalSemanticEvidence | None = None
    abstention: CanonicalSemanticEvidenceProductionAbstention | None = None

    def __post_init__(self) -> None:
        if (self.evidence is None) == (self.abstention is None):
            raise ValueError("production result requires exactly one outcome")
        if self.abstention is not None and not isinstance(
            self.abstention, CanonicalSemanticEvidenceProductionAbstention
        ):
            raise TypeError("production result requires a typed abstention")
        if self.evidence is not None and not isinstance(self.evidence, CanonicalSemanticEvidence):
            raise TypeError("accepted production result requires canonical evidence")


class _CanonicalSemanticEvidenceProductionSignal(Exception):
    """Private typed short-circuit for expected proposal abstentions."""

    def __init__(self, abstention: CanonicalSemanticEvidenceProductionAbstention) -> None:
        super().__init__()
        self.abstention = abstention


def _stable_dag_witness_from_raw(
    raw: DecisionDagRouteWitness,
    identities: Mapping[int, StableBlockIdentity],
    abstain,
) -> SemanticDecisionDagWitness:
    """Canonicalize a typed DAG proposal without evaluating its route.

    Route semantics and CFG reciprocity are intentionally deferred to the
    transaction binder.  This adapter only resolves stable identity/anchor
    coordinates and rejects malformed proposal shape.
    """
    alias_pairs = tuple((int(source), int(target)) for source, target in raw.aliases)
    alias_targets_by_source: dict[int, set[int]] = {}
    for source, target in alias_pairs:
        alias_targets_by_source.setdefault(source, set()).add(target)
    comparison_nodes = tuple(int(serial) for serial, _comparison in raw.comparisons)
    if any(len(targets) > 1 for targets in alias_targets_by_source.values()):
        abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_ALIAS_CONFLICTING_TARGET)
    if len(set(alias_pairs)) != len(alias_pairs):
        abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_ALIAS_DUPLICATE_SOURCE)
    if len(set(comparison_nodes)) != len(comparison_nodes):
        abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_COMPARISON_DUPLICATE_NODE)
    if set(alias_targets_by_source) & set(comparison_nodes):
        abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_ALIAS_COMPARISON_OVERLAP)
    alias_targets = {source: next(iter(targets)) for source, targets in alias_targets_by_source.items()}
    for source in alias_targets:
        seen: set[int] = set()
        current = source
        while current in alias_targets:
            if current in seen:
                abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_ALIAS_CYCLE)
            seen.add(current)
            current = alias_targets[current]
    if (
        len(raw.path_serials) != len(raw.path_anchors)
        or not raw.path_serials
        or int(raw.path_serials[0]) != int(raw.entry_serial)
    ):
        abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_PATH_SHAPE)
    path_points: list[SemanticCorridorPoint] = []
    for serial, anchor in zip(raw.path_serials, raw.path_anchors):
        identity = identities.get(int(serial))
        if identity is None or not identity.native_ranges.contains(int(anchor)):
            abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_PATH_ANCHOR)
        path_points.append(SemanticCorridorPoint(identity, int(anchor)))
    entry_identity = identities.get(int(raw.entry_serial))
    if entry_identity is None or not entry_identity.native_ranges.contains(int(raw.entry_anchor_ea)):
        abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_ENTRY_ANCHOR)
    comparisons: list[SemanticDagComparison] = []
    path_anchor_by_serial = {
        int(serial): int(anchor)
        for serial, anchor in zip(raw.path_serials, raw.path_anchors)
    }
    for serial, comparison in raw.comparisons:
        node_identity = identities.get(int(serial))
        true_identity = identities.get(int(comparison.true_target))
        false_identity = identities.get(int(comparison.false_target))
        node_anchor = path_anchor_by_serial.get(
            int(serial),
            stable_block_identity_semantic_anchor(node_identity)
            if node_identity is not None
            else None,
        )
        if node_identity is None or true_identity is None or false_identity is None or node_anchor is None:
            abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_COMPARISON_IDENTITY)
        comparisons.append(
            SemanticDagComparison(
                node=SemanticCorridorPoint(node_identity, int(node_anchor)),
                operation=str(comparison.op),
                constant=int(comparison.const),
                true_target=SemanticCorridorPoint(
                    true_identity,
                    stable_block_identity_semantic_anchor(true_identity),
                ),
                false_target=SemanticCorridorPoint(
                    false_identity,
                    stable_block_identity_semantic_anchor(false_identity),
                ),
            )
        )
    aliases: list[tuple[SemanticCorridorPoint, SemanticCorridorPoint]] = []
    for source_serial, target_serial in raw.aliases:
        source_identity = identities.get(int(source_serial))
        target_identity = identities.get(int(target_serial))
        if source_identity is None or target_identity is None:
            abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_ALIAS_IDENTITY)
        aliases.append(
            (
                SemanticCorridorPoint(
                    source_identity,
                    stable_block_identity_semantic_anchor(source_identity),
                ),
                SemanticCorridorPoint(
                    target_identity,
                    stable_block_identity_semantic_anchor(target_identity),
                ),
            )
        )
    return SemanticDecisionDagWitness(
        state_identity=raw.state_identity,
        state_constant=raw.state_constant,
        entry=SemanticCorridorPoint(entry_identity, int(raw.entry_anchor_ea)),
        path=tuple(path_points),
        comparisons=tuple(comparisons),
        aliases=tuple(aliases),
    )


def build_canonical_semantic_evidence(
    facts: tuple[SemanticRouteFact, ...],
    context: CanonicalSemanticEvidenceProductionContext,
) -> CanonicalSemanticEvidenceProductionResult:
    """Canonicalize typed recovery facts against stable source coordinates.

    This producer deliberately does not replay graph semantics.  The immutable
    transaction binder owns fixpoint, DAG, corridor, and write validation.
    """
    active_fact: SemanticRouteFact | None = None

    def coordinate() -> CanonicalSemanticEvidenceProductionFactCoordinate | None:
        if active_fact is None:
            return None
        return CanonicalSemanticEvidenceProductionFactCoordinate(
            fact_kind=active_fact.kind,
            owner_serial=active_fact.owner_serial,
            source_serial=active_fact.source_serial,
            source_instruction_ea=active_fact.source_instruction_ea,
            target_serial=active_fact.target_serial,
            state_constant=active_fact.state_constant,
        )

    def result_abstention(
        reason: CanonicalSemanticEvidenceProductionReason,
        stage: CanonicalSemanticEvidenceProductionStage,
        *,
        detail: str | None = None,
    ) -> CanonicalSemanticEvidenceProductionResult:
        return CanonicalSemanticEvidenceProductionResult(
            abstention=CanonicalSemanticEvidenceProductionAbstention(
                reason=reason,
                stage=stage,
                coordinate=coordinate(),
                detail=detail,
            )
        )

    def abstain(
        reason: CanonicalSemanticEvidenceProductionReason,
        stage: CanonicalSemanticEvidenceProductionStage = CanonicalSemanticEvidenceProductionStage.FACT,
        *,
        detail: str | None = None,
    ) -> None:
        raise _CanonicalSemanticEvidenceProductionSignal(
            CanonicalSemanticEvidenceProductionAbstention(
                reason=reason,
                stage=stage,
                coordinate=coordinate(),
                detail=detail,
            )
        )

    if not facts:
        return result_abstention(
            CanonicalSemanticEvidenceProductionReason.EMPTY_GROUP,
            CanonicalSemanticEvidenceProductionStage.GROUP,
        )
    if int(context.generation) < 0:
        return result_abstention(
            CanonicalSemanticEvidenceProductionReason.NEGATIVE_GENERATION,
            CanonicalSemanticEvidenceProductionStage.CONTEXT,
        )
    identities = dict(context.identities_by_serial)
    blocks = {block.serial: block for block in context.blocks}
    proofs: list[SemanticRouteProof] = []
    proof_facts: list[SemanticRouteFact] = []

    def append_proof(proof: SemanticRouteProof) -> None:
        if active_fact is None:
            raise SemanticRouteEvidenceRejected("canonical route proof has no active fact")
        proofs.append(proof)
        proof_facts.append(active_fact)

    partition_facts = tuple(
        fact for fact in facts
        if fact.kind is SemanticRouteFactKind.STATE_PARTITION
        and fact.partition_witness is not None
    )
    for group in {
        fact.partition_witness for fact in partition_facts
        if fact.partition_witness is not None
    }:
        group_owners = {
            int(fact.owner_serial)
            for fact in partition_facts
            if fact.partition_witness is not None
            and fact.partition_witness.group_id == group.group_id
        }
        if group_owners != {int(item.owner_serial) for item in group.members}:
            return result_abstention(
                CanonicalSemanticEvidenceProductionReason.PARTITION_GROUP_INCOMPLETE,
                CanonicalSemanticEvidenceProductionStage.GROUP,
            )
    try:
        for fact in facts:
            active_fact = fact
            if fact.kind is SemanticRouteFactKind.BOOTSTRAP:
                witness = fact.bootstrap_witness
                owner = identities.get(int(fact.owner_serial))
                source = identities.get(int(fact.source_serial))
                target = identities.get(int(fact.target_serial))
                if witness is None or owner is None or source is None or target is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_IDENTITY_MISSING)
                if not isinstance(witness, SemanticBootstrapRouteWitness):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_CORRIDOR_INVALID)
                if not isinstance(witness.state_identity, StorageIdentity):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_STATE_WRITE_INVALID)
                try:
                    witness_state_constant = int(witness.state_constant) & 0xFFFFFFFF
                    witness_state_write_ea = int(witness.source_instruction_ea)
                    witness_state_width = int(witness.state_width)
                    fact_state_constant = int(fact.state_constant) & 0xFFFFFFFF
                except (TypeError, ValueError, AttributeError, OverflowError):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_STATE_WRITE_INVALID)
                if fact_state_constant != witness_state_constant:
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_STATE_WRITE_INVALID)
                if fact.target_anchor_ea is not None and not isinstance(fact.target_anchor_ea, int):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_CORRIDOR_INVALID)
                if (
                    not isinstance(witness.corridor_serials, tuple)
                    or not isinstance(witness.corridor_anchors, tuple)
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_CORRIDOR_INVALID)
                if (
                    not isinstance(witness.preserved_effect_sites, tuple)
                    or any(not isinstance(site, InstructionEffectSite) for site in witness.preserved_effect_sites)
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_EFFECTS_INVALID)
                if not isinstance(witness.decision_dag_witness, DecisionDagRouteWitness):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_DAG_INVALID)
                try:
                    dispatcher_serial = int(witness.dispatcher_serial)
                    entry_serial = int(witness.entry_serial)
                    source_serial = int(witness.source_serial)
                    corridor_serials = tuple(int(serial) for serial in witness.corridor_serials)
                    corridor_anchors = tuple(int(anchor) for anchor in witness.corridor_anchors)
                except (TypeError, ValueError, AttributeError, OverflowError):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_CORRIDOR_INVALID)
                dispatcher = identities.get(dispatcher_serial)
                entry = identities.get(entry_serial)
                if dispatcher is None or entry is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_IDENTITY_MISSING)
                if (
                    len(corridor_serials) < 2
                    or len(corridor_serials) != len(corridor_anchors)
                    or corridor_serials[0] != source_serial
                    or corridor_serials[-1] != dispatcher_serial
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_CORRIDOR_INVALID)
                corridor: list[SemanticCorridorPoint] = []
                for serial, anchor in zip(corridor_serials, corridor_anchors):
                    identity = identities.get(serial)
                    if identity is None or not identity.native_ranges.contains(anchor):
                        abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_CORRIDOR_INVALID)
                    corridor.append(SemanticCorridorPoint(identity, anchor))
                if not source.native_ranges.contains(witness_state_write_ea):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_STATE_WRITE_INVALID)
                if witness_state_width != 4:
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_STATE_WRITE_INVALID)
                owner_interval = next(
                    (
                        item
                        for item in owner.native_ranges.intervals
                        if item.start_ea <= int(corridor[-2].anchor_ea) < item.end_ea
                    ),
                    None,
                )
                if owner_interval is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_OWNER_RANGE_MISSING)
                source_interval = next(
                    (
                        item
                        for item in source.native_ranges.intervals
                        if item.start_ea <= witness_state_write_ea < item.end_ea
                    ),
                    None,
                )
                if source_interval is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_OWNER_RANGE_MISSING)
                def bootstrap_dag_abstain(
                    _reason: CanonicalSemanticEvidenceProductionReason,
                ) -> None:
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_DAG_INVALID)

                try:
                    stable_dag_witness = _stable_dag_witness_from_raw(
                        witness.decision_dag_witness, identities, bootstrap_dag_abstain
                    )
                except (TypeError, ValueError, AttributeError, IndexError, OverflowError):
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_DAG_INVALID)
                try:
                    state_write = SemanticStateWriteProof(
                        identity=source,
                        instruction_ea=witness_state_write_ea,
                        state_variable=witness.state_identity,
                        width=4,
                        state_constant=witness_state_constant,
                        corridor_instruction_eas=(witness_state_write_ea,),
                        authority_transfer_ea=None,
                        preserved_call_instruction_eas=(),
                        delivery_kind=SemanticStateWriteDeliveryKind.INDIRECT,
                    )
                    state_dag = SemanticStateDagProof(
                        witness=stable_dag_witness,
                        source_identity=owner,
                        source_anchor_ea=int(corridor[-2].anchor_ea),
                        target_identity=target,
                        target_anchor_ea=int(fact.target_anchor_ea or stable_block_identity_semantic_anchor(target)),
                        entry_identity=stable_dag_witness.entry.identity,
                        entry_anchor_ea=int(stable_dag_witness.entry.anchor_ea),
                        path=stable_dag_witness.path,
                    )
                    bootstrap = SemanticBootstrapProof(
                        entry=SemanticCorridorPoint(entry, stable_block_identity_semantic_anchor(entry)),
                        source=corridor[0],
                        owner=corridor[-2],
                        dispatcher=corridor[-1],
                        corridor=tuple(corridor),
                        state_write=state_write,
                        state_dag=state_dag,
                        preserved_effect_sites=witness.preserved_effect_sites,
                    )
                    append_proof(
                        SemanticRouteProof(
                        proof_id=f"bootstrap@0x{witness_state_write_ea:X}:{fact_state_constant:X}",
                        atomic_group_id=context.atomic_group_id,
                        proof_kind=SemanticRouteProofKind.BOOTSTRAP,
                        shape=SemanticRouteShape.DIRECT,
                        source_identity=owner,
                        source_anchor_ea=int(corridor[-2].anchor_ea),
                        source_owner_identity=None,
                        source_owner_anchor_ea=None,
                        delivery_region=NativeEaInterval(owner_interval.start_ea, owner_interval.end_ea),
                        destinations=(
                            SemanticRouteDestination(
                                role=SemanticEdgeRole.DIRECT,
                                state_constant=fact_state_constant,
                                target_identity=target,
                                target_anchor_ea=int(fact.target_anchor_ea or stable_block_identity_semantic_anchor(target)),
                            ),
                        ),
                        state_write=state_write,
                        state_dag=state_dag,
                        bootstrap=bootstrap,
                        )
                    )
                except SemanticRouteEvidenceRejected:
                    abstain(CanonicalSemanticEvidenceProductionReason.BOOTSTRAP_SUBMODEL_REJECTED)
                continue
            if fact.kind is SemanticRouteFactKind.STATE_PARTITION:
                witness = fact.partition_witness
                if witness is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_MISSING_WITNESS)
                member = next(
                    (item for item in witness.members if int(item.owner_serial) == int(fact.owner_serial)),
                    None,
                )
                feeder = identities.get(int(witness.feeder_serial))
                owner = identities.get(int(fact.owner_serial))
                target = identities.get(int(fact.target_serial))
                if member is None or feeder is None or owner is None or target is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_IDENTITY_MISSING)
                owner_anchor = fact.owner_anchor_ea or stable_block_identity_semantic_anchor(owner)
                feeder_anchor = stable_block_identity_semantic_anchor(feeder)
                target_anchor = fact.target_anchor_ea or stable_block_identity_semantic_anchor(target)
                if not owner.native_ranges.contains(owner_anchor) or not target.native_ranges.contains(target_anchor):
                    abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_ANCHOR_MISSING)
                feeder_interval = next(
                    (
                        interval
                        for interval in feeder.native_ranges.intervals
                        if interval.start_ea
                        <= int(witness.feeder_instruction_ea)
                        < interval.end_ea
                    ),
                    None,
                )
                if feeder_interval is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_DELIVERY_REGION_MISSING)
                members = tuple(
                    SemanticPartitionMemberProof(
                        owner_identity=identities[int(item.owner_serial)],
                        owner_anchor_ea=stable_block_identity_semantic_anchor(identities[int(item.owner_serial)]),
                        state_constant=int(item.state_constant),
                    )
                    for item in witness.members
                )
                partition_proof = SemanticStatePartitionProof(
                    group_id=_canonical_partition_group_id(
                        feeder,
                        witness.feeder_instruction_ea,
                        witness.state_identity,
                        members,
                    ),
                    feeder_identity=feeder,
                    feeder_anchor_ea=feeder_anchor,
                    feeder_instruction_ea=witness.feeder_instruction_ea,
                    state_identity=witness.state_identity,
                    members=members,
                )
                raw_dag = fact.decision_dag_witness
                if raw_dag is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_MISSING_DECISION_DAG)
                if raw_dag.state_identity != context.state_identity:
                    abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_STATE_IDENTITY_MISMATCH)
                stable_partition_dag = _stable_dag_witness_from_raw(
                    raw_dag, identities, abstain
                )
                if (
                    len(raw_dag.path_serials) != len(raw_dag.path_anchors)
                    or not raw_dag.path_serials
                    or int(raw_dag.path_serials[0]) != int(raw_dag.entry_serial)
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_DAG_PATH_SHAPE)
                path_points: list[SemanticCorridorPoint] = []
                for serial, anchor in zip(raw_dag.path_serials, raw_dag.path_anchors):
                    identity = identities.get(int(serial))
                    if identity is None or not identity.native_ranges.contains(int(anchor)):
                        abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_DAG_PATH_ANCHOR)
                    path_points.append(SemanticCorridorPoint(identity, int(anchor)))
                entry_identity = identities.get(int(raw_dag.entry_serial))
                if entry_identity is None or not entry_identity.native_ranges.contains(int(raw_dag.entry_anchor_ea)):
                    abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_DAG_ENTRY_ANCHOR)
                comparisons: list[SemanticDagComparison] = []
                for serial, comparison in raw_dag.comparisons:
                    node_identity = identities.get(int(serial))
                    true_identity = identities.get(int(comparison.true_target))
                    false_identity = identities.get(int(comparison.false_target))
                    node_anchor = next(
                        (int(anchor) for path_serial, anchor in zip(raw_dag.path_serials, raw_dag.path_anchors)
                         if int(path_serial) == int(serial)),
                        stable_block_identity_semantic_anchor(node_identity)
                        if node_identity is not None else None,
                    )
                    if node_identity is None or true_identity is None or false_identity is None or node_anchor is None:
                        abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_DAG_COMPARISON_IDENTITY)
                    comparisons.append(
                        SemanticDagComparison(
                            node=SemanticCorridorPoint(node_identity, int(node_anchor)),
                            operation=str(comparison.op),
                            constant=int(comparison.const),
                            true_target=SemanticCorridorPoint(
                                true_identity,
                                stable_block_identity_semantic_anchor(true_identity),
                            ),
                            false_target=SemanticCorridorPoint(
                                false_identity,
                                stable_block_identity_semantic_anchor(false_identity),
                            ),
                        )
                    )
                aliases: list[tuple[SemanticCorridorPoint, SemanticCorridorPoint]] = []
                for source_serial, target_serial in raw_dag.aliases:
                    source_identity = identities.get(int(source_serial))
                    target_identity = identities.get(int(target_serial))
                    if source_identity is None or target_identity is None:
                        abstain(CanonicalSemanticEvidenceProductionReason.PARTITION_DAG_ALIAS_IDENTITY)
                    aliases.append(
                        (
                            SemanticCorridorPoint(source_identity, stable_block_identity_semantic_anchor(source_identity)),
                            SemanticCorridorPoint(target_identity, stable_block_identity_semantic_anchor(target_identity)),
                        )
                    )
                dag_witness = stable_partition_dag
                dag_proof = SemanticStateDagProof(
                    witness=dag_witness,
                    source_identity=feeder,
                    source_anchor_ea=int(fact.source_instruction_ea),
                    target_identity=target,
                    target_anchor_ea=int(target_anchor),
                    entry_identity=entry_identity,
                    entry_anchor_ea=int(raw_dag.entry_anchor_ea),
                    path=tuple(path_points),
                )
                append_proof(
                    SemanticRouteProof(
                        proof_id=_canonical_partition_proof_id(
                            partition_proof.group_id,
                            owner,
                            target,
                            witness.state_identity,
                            member.state_constant,
                        ),
                        atomic_group_id=context.atomic_group_id,
                        proof_kind=SemanticRouteProofKind.STATE_PARTITION,
                        shape=SemanticRouteShape.DIRECT,
                        source_identity=feeder,
                        source_anchor_ea=witness.feeder_instruction_ea,
                        source_owner_identity=owner,
                        source_owner_anchor_ea=owner_anchor,
                        delivery_region=NativeEaInterval(
                            feeder_interval.start_ea,
                            feeder_interval.end_ea,
                        ),
                        destinations=(SemanticRouteDestination(
                            role=SemanticEdgeRole.DIRECT,
                            state_constant=int(member.state_constant),
                            target_identity=target,
                            target_anchor_ea=target_anchor,
                        ),),
                        state_partition=partition_proof,
                        state_dag=dag_proof,
                    )
                )
                continue
            if fact.kind is SemanticRouteFactKind.STATE_CARRIER:
                witness = fact.carrier_witness
                if witness is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.CARRIER_MISSING_WITNESS)
                if (
                    int(witness.source_serial) != int(fact.source_serial)
                    or int(witness.source_serial) != int(fact.owner_serial)
                    or int(witness.state) != int(fact.state_constant)
                    or witness.state_identity != context.state_identity
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.CARRIER_FACT_IDENTITY_MISMATCH)
                owner = identities.get(int(fact.owner_serial))
                source = identities.get(int(witness.source_serial))
                feeder = identities.get(int(witness.feeder_serial))
                comparison = identities.get(int(witness.comparison_entry_serial))
                target = identities.get(int(fact.target_serial))
                if (
                    owner is None
                    or source is None
                    or feeder is None
                    or comparison is None
                    or target is None
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.CARRIER_IDENTITY_MISSING)
                if not source.native_ranges.contains(int(fact.source_instruction_ea)):
                    abstain(CanonicalSemanticEvidenceProductionReason.CARRIER_SOURCE_ANCHOR_MISSING)
                if int(fact.source_instruction_ea) not in source.exact_instruction_eas:
                    abstain(CanonicalSemanticEvidenceProductionReason.CARRIER_SOURCE_INSTRUCTION_MISSING)
                anchors = (
                    (source, int(fact.source_instruction_ea)),
                    (feeder, stable_block_identity_semantic_anchor(feeder)),
                    (comparison, stable_block_identity_semantic_anchor(comparison)),
                )
                if any(
                    not identity.native_ranges.contains(int(anchor))
                    for identity, anchor in anchors
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.CARRIER_ANCHOR_MISSING)
                target_anchor = fact.target_anchor_ea or stable_block_identity_semantic_anchor(target)
                if not target.native_ranges.contains(int(target_anchor)):
                    abstain(CanonicalSemanticEvidenceProductionReason.CARRIER_TARGET_ANCHOR_MISSING)
                source_interval = next(
                    (
                        item
                        for item in source.native_ranges.intervals
                        if item.start_ea <= int(fact.source_instruction_ea) < item.end_ea
                    ),
                    None,
                )
                if source_interval is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.CARRIER_SOURCE_RANGE_MISSING)
                carrier_proof = SemanticStateCarrierProof(
                    carrier=witness.carrier,
                    owner_identity=owner,
                    owner_anchor_ea=(
                        fact.owner_anchor_ea
                        or stable_block_identity_semantic_anchor(owner)
                    ),
                    source_identity=source,
                    source_anchor_ea=int(fact.source_instruction_ea),
                    feeder_identity=feeder,
                    feeder_anchor_ea=stable_block_identity_semantic_anchor(feeder),
                    comparison_entry_identity=comparison,
                    comparison_entry_anchor_ea=stable_block_identity_semantic_anchor(comparison),
                    state_identity=witness.state_identity,
                    state_constant=int(witness.state),
                    requires_feeder_clone=bool(witness.requires_feeder_clone),
                    corridor=tuple(
                        SemanticCorridorPoint(identity, anchor)
                        for identity, anchor in anchors
                    ),
                )
                append_proof(
                    SemanticRouteProof(
                        proof_id=(
                            f"state-carrier@0x{int(fact.source_instruction_ea):X}:"
                            f"{int(fact.state_constant):X}"
                        ),
                        atomic_group_id=context.atomic_group_id,
                        proof_kind=SemanticRouteProofKind.STATE_CARRIER,
                        shape=SemanticRouteShape.DIRECT,
                        source_identity=source,
                        source_anchor_ea=int(fact.source_instruction_ea),
                        source_owner_identity=(None if owner == source else owner),
                        source_owner_anchor_ea=(
                            None
                            if owner == source
                            else (
                                fact.owner_anchor_ea
                                or stable_block_identity_semantic_anchor(owner)
                            )
                        ),
                        delivery_region=NativeEaInterval(
                            source_interval.start_ea, source_interval.end_ea
                        ),
                        destinations=(
                            SemanticRouteDestination(
                                role=SemanticEdgeRole.DIRECT,
                                state_constant=int(witness.state),
                                target_identity=target,
                                target_anchor_ea=int(target_anchor),
                            ),
                        ),
                        state_carrier=carrier_proof,
                    )
                )
                continue
            if (
                fact.kind is SemanticRouteFactKind.DECISION_DAG
                and fact.decision_dag_witness is not None
            ):
                witness = fact.decision_dag_witness
                source = identities.get(int(fact.source_serial))
                target = identities.get(int(fact.target_serial))
                if source is None or target is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_IDENTITY_MISSING)
                if witness.state_identity != context.state_identity:
                    abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_STATE_IDENTITY_MISMATCH)
                stable_witness = _stable_dag_witness_from_raw(
                    witness, identities, abstain
                )
                entry = stable_witness.entry.identity
                path_points = stable_witness.path
                target_anchor = fact.target_anchor_ea or stable_block_identity_semantic_anchor(target)
                source_anchor = fact.source_instruction_ea
                if not source.native_ranges.contains(int(source_anchor)) or not target.native_ranges.contains(int(target_anchor)):
                    abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_ROUTE_ANCHOR_MISSING)
                source_interval = next(
                    (
                        item for item in source.native_ranges.intervals
                        if item.start_ea <= int(source_anchor) < item.end_ea
                    ),
                    None,
                )
                if source_interval is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.DECISION_DAG_SOURCE_RANGE_MISSING)
                dag_proof = SemanticStateDagProof(
                    witness=stable_witness,
                    source_identity=source,
                    source_anchor_ea=int(source_anchor),
                    target_identity=target,
                    target_anchor_ea=int(target_anchor),
                    entry_identity=entry,
                    entry_anchor_ea=int(stable_witness.entry.anchor_ea),
                    path=tuple(path_points),
                )
                state_write = SemanticStateWriteProof(
                    identity=source,
                    instruction_ea=int(source_anchor),
                    state_variable=context.state_identity,
                    width=4,
                    state_constant=int(fact.state_constant),
                    corridor_instruction_eas=(int(source_anchor),),
                    authority_transfer_ea=None,
                    preserved_call_instruction_eas=(),
                    delivery_kind=SemanticStateWriteDeliveryKind.INDIRECT,
                )
                append_proof(
                    SemanticRouteProof(
                        proof_id=(
                            f"state-dag@{source.diagnostic_label()}:"
                            f"{int(fact.state_constant):X}"
                        ),
                        atomic_group_id=context.atomic_group_id,
                        proof_kind=SemanticRouteProofKind.STATE_DAG,
                        shape=SemanticRouteShape.DIRECT,
                        source_identity=source,
                        source_anchor_ea=int(source_anchor),
                        delivery_region=NativeEaInterval(
                            source_interval.start_ea, source_interval.end_ea
                        ),
                        destinations=(
                            SemanticRouteDestination(
                                role=SemanticEdgeRole.DIRECT,
                                state_constant=int(fact.state_constant),
                                target_identity=target,
                                target_anchor_ea=int(target_anchor),
                            ),
                        ),
                        state_write=state_write,
                        state_dag=dag_proof,
                    )
                )
                continue
            if fact.kind is SemanticRouteFactKind.STATE_TRANSFORM:
                witness = fact.transform_witness
                if witness is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.TRANSFORM_MISSING_WITNESS)
                if (
                    int(witness.source_serial) != int(fact.owner_serial)
                    or int(witness.source_serial) != int(fact.source_serial)
                    or int(witness.state) != int(fact.state_constant)
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.TRANSFORM_FACT_IDENTITY_MISMATCH)
                source = identities.get(int(witness.source_serial))
                feeder = identities.get(int(witness.feeder_serial))
                comparison = identities.get(int(witness.comparison_entry_serial))
                state_feeder = (
                    None
                    if witness.state_feeder_serial is None
                    else identities.get(int(witness.state_feeder_serial))
                )
                target = identities.get(fact.target_serial)
                if source is None or feeder is None or comparison is None or target is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.TRANSFORM_IDENTITY_MISSING)
                if witness.state_feeder_serial is not None and state_feeder is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.TRANSFORM_STATE_FEEDER_MISSING)
                anchors = (
                    (source, witness.source_ea),
                    (feeder, witness.feeder_ea),
                    (comparison, witness.comparison_entry_ea),
                )
                if witness.state_feeder_ea is not None:
                    if state_feeder is None:
                        abstain(CanonicalSemanticEvidenceProductionReason.TRANSFORM_STATE_FEEDER_ANCHOR_MISSING)
                    anchors += ((state_feeder, witness.state_feeder_ea),)
                if any(
                    not identity.native_ranges.contains(int(anchor))
                    for identity, anchor in anchors
                ):
                    abstain(CanonicalSemanticEvidenceProductionReason.TRANSFORM_ANCHOR_MISSING)
                target_anchor = fact.target_anchor_ea or stable_block_identity_semantic_anchor(target)
                if not target.native_ranges.contains(target_anchor):
                    abstain(CanonicalSemanticEvidenceProductionReason.TRANSFORM_TARGET_ANCHOR_MISSING)
                source_interval = next(
                    (
                        item
                        for item in source.native_ranges.intervals
                        if item.start_ea <= int(witness.source_ea) < item.end_ea
                    ),
                    None,
                )
                if source_interval is None:
                    abstain(CanonicalSemanticEvidenceProductionReason.TRANSFORM_SOURCE_RANGE_MISSING)
                transform_proof = SemanticStateTransformProof(
                    operation=witness.operation,
                    program=tuple(witness.program),
                    source_bindings=tuple(witness.source_bindings),
                    owner_identity=source,
                    owner_anchor_ea=int(witness.source_ea),
                    source_identity=source,
                    source_anchor_ea=int(witness.source_ea),
                    feeder_identity=feeder,
                    feeder_anchor_ea=int(witness.feeder_ea),
                    comparison_entry_identity=comparison,
                    comparison_entry_anchor_ea=int(witness.comparison_entry_ea),
                    state_feeder_identity=state_feeder,
                    state_feeder_anchor_ea=witness.state_feeder_ea,
                    state_identity=witness.state_identity,
                    state_constant=int(witness.state),
                    corridor=tuple(
                        SemanticCorridorPoint(
                            identities.get(serial),
                            anchor,
                        )
                        for serial, anchor in (
                            (int(witness.source_serial), int(witness.source_ea)),
                            (int(witness.feeder_serial), int(witness.feeder_ea)),
                            *(
                                ((int(witness.state_feeder_serial), int(witness.state_feeder_ea)),)
                                if witness.state_feeder_serial is not None
                                and witness.state_feeder_ea is not None
                                else ()
                            ),
                            (
                                int(witness.comparison_entry_serial),
                                int(witness.comparison_entry_ea),
                            ),
                        )
                    ),
                    corridor_instruction_eas=tuple(
                        sorted(
                            {
                                int(witness.source_ea),
                                int(witness.feeder_ea),
                                int(witness.comparison_entry_ea),
                                *(
                                    (int(witness.state_feeder_ea),)
                                    if witness.state_feeder_ea is not None
                                    else ()
                                ),
                            }
                        )
                    ),
                )
                append_proof(
                    SemanticRouteProof(
                        proof_id=f"state-transform@0x{int(witness.source_ea):X}:{int(witness.state):X}",
                        atomic_group_id=context.atomic_group_id,
                        proof_kind=SemanticRouteProofKind.STATE_TRANSFORM,
                        shape=SemanticRouteShape.DIRECT,
                        source_identity=source,
                        source_anchor_ea=int(witness.source_ea),
                        source_owner_identity=None,
                        source_owner_anchor_ea=None,
                        delivery_region=NativeEaInterval(
                            source_interval.start_ea, source_interval.end_ea
                        ),
                        destinations=(
                            SemanticRouteDestination(
                                role=SemanticEdgeRole.DIRECT,
                                state_constant=int(witness.state),
                                target_identity=target,
                                target_anchor_ea=int(target_anchor),
                            ),
                        ),
                        state_transform=transform_proof,
                    )
                )
                continue
            owner = identities.get(fact.owner_serial)
            source = identities.get(fact.source_serial)
            target = identities.get(fact.target_serial)
            if owner is None or source is None or target is None:
                abstain(CanonicalSemanticEvidenceProductionReason.ASSIGNMENT_IDENTITY_MISSING)
            if not target.exact_instruction_eas or not source.exact_instruction_eas:
                abstain(CanonicalSemanticEvidenceProductionReason.ASSIGNMENT_ANCHOR_SET_MISSING)
            owner_anchor = fact.owner_anchor_ea or stable_block_identity_semantic_anchor(owner)
            target_anchor = fact.target_anchor_ea or stable_block_identity_semantic_anchor(target)
            if (
                not owner.native_ranges.contains(owner_anchor)
                or not target.native_ranges.contains(target_anchor)
            ):
                abstain(
                    CanonicalSemanticEvidenceProductionReason.ASSIGNMENT_ANCHOR_MISSING,
                    detail=(
                        f"owner_anchor=0x{int(owner_anchor):X} "
                        f"target_anchor=0x{int(target_anchor):X}"
                    ),
                )
            if not source.native_ranges.contains(fact.source_instruction_ea):
                abstain(CanonicalSemanticEvidenceProductionReason.ASSIGNMENT_SOURCE_RANGE_MISSING)
            if fact.source_instruction_ea not in source.exact_instruction_eas:
                abstain(CanonicalSemanticEvidenceProductionReason.ASSIGNMENT_SOURCE_ANCHOR_MISSING)
            interval = next(
                (
                    item
                    for item in source.native_ranges.intervals
                    if item.start_ea <= fact.source_instruction_ea < item.end_ea
                ),
                None,
            )
            if interval is None:
                abstain(CanonicalSemanticEvidenceProductionReason.ASSIGNMENT_DELIVERY_RANGE_MISSING)
            proof_id = (
                f"decision-dag-state-assignment@0x{fact.source_instruction_ea:X}:"
                f"{fact.state_constant:X}"
            )
            append_proof(
                SemanticRouteProof(
                    proof_id=proof_id,
                    atomic_group_id=context.atomic_group_id,
                    proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
                    shape=SemanticRouteShape.DIRECT,
                    source_identity=source,
                    source_anchor_ea=fact.source_instruction_ea,
                    source_owner_identity=None if owner == source else owner,
                    source_owner_anchor_ea=(
                        None if owner == source else owner_anchor
                    ),
                    delivery_region=NativeEaInterval(interval.start_ea, interval.end_ea),
                    destinations=(
                        SemanticRouteDestination(
                            role=SemanticEdgeRole.DIRECT,
                            state_constant=fact.state_constant,
                            target_identity=target,
                            target_anchor_ea=target_anchor,
                        ),
                    ),
                    state_write=SemanticStateWriteProof(
                        identity=source,
                        instruction_ea=fact.source_instruction_ea,
                        state_variable=context.state_identity,
                        width=4,
                        state_constant=fact.state_constant,
                        corridor_instruction_eas=(fact.source_instruction_ea,),
                        authority_transfer_ea=None,
                        preserved_call_instruction_eas=(),
                        delivery_kind=SemanticStateWriteDeliveryKind.INDIRECT,
                    ),
                    diagnostic_provenance=(
                        ()
                        if fact.fact_id is None
                        else (("fact_id", fact.fact_id),)
                    ),
                )
            )
        try:
            if len(proofs) != len(proof_facts):
                return result_abstention(
                    CanonicalSemanticEvidenceProductionReason.CANONICAL_MODEL_REJECTED,
                    CanonicalSemanticEvidenceProductionStage.CANONICAL_MODEL,
                )
            diagnostic_proofs: list[SemanticRouteProof] = []
            for proof, fact in zip(proofs, proof_facts):
                provenance = tuple(
                    item
                    for item in proof.diagnostic_provenance
                    if item[0] != "fact_id"
                )
                if fact.fact_id is not None:
                    provenance += (("fact_id", fact.fact_id),)
                diagnostic_proofs.append(
                    replace(proof, diagnostic_provenance=provenance)
                )
            evidence = canonical_semantic_evidence_from_proofs(
                native_key=context.native_key,
                generation=context.generation,
                proofs=tuple(diagnostic_proofs),
            )
        except SemanticRouteEvidenceRejected:
            return result_abstention(
                CanonicalSemanticEvidenceProductionReason.CANONICAL_MODEL_REJECTED,
                CanonicalSemanticEvidenceProductionStage.CANONICAL_MODEL,
            )
        return CanonicalSemanticEvidenceProductionResult(evidence=evidence)
    except _CanonicalSemanticEvidenceProductionSignal as signal:
        return CanonicalSemanticEvidenceProductionResult(
            abstention=signal.abstention
        )


def canonical_terminal_state_targets(
    evidence: CanonicalSemanticEvidence | None,
    *,
    state_variable: StorageIdentity,
) -> tuple[tuple[int, int], ...]:
    """Project exact terminal state targets from one canonical generation.

    The terminal-return proof validator already requires the state write,
    destination, return carrier, and their exact native anchors to agree.  This
    projection therefore exposes only the state/target identity needed by
    consumers whose live graph has canonicalized the terminal block away.
    """
    if evidence is None:
        return ()
    if not isinstance(evidence, CanonicalSemanticEvidence):
        raise TypeError("terminal state target projection requires canonical evidence")
    if not isinstance(state_variable, StorageIdentity):
        raise TypeError("terminal state target projection requires storage identity")
    return tuple(
        sorted(
            {
                (
                    int(destination.state_constant) & 0xFFFFFFFF,
                    int(destination.target_anchor_ea),
                )
                for proof in evidence.route_proofs
                if proof.proof_kind is SemanticRouteProofKind.TERMINAL_RETURN
                and proof.state_write is not None
                and proof.state_write.state_variable == state_variable
                for destination in proof.destinations
                if destination.terminal
            }
        )
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
class BoundSemanticStateTransform:
    """A state-transform witness rebound to exact current graph blocks."""

    evidence: SemanticStateTransformProof
    owner: BoundSemanticBlock
    source: BoundSemanticBlock
    feeder: BoundSemanticBlock
    comparison_entry: BoundSemanticBlock
    state_feeder: BoundSemanticBlock | None = None


@dataclass(frozen=True, slots=True)
class BoundSemanticStateCarrier:
    """A source-owned CONST32 carrier proof rebound to current blocks."""

    evidence: SemanticStateCarrierProof
    owner: BoundSemanticBlock
    source: BoundSemanticBlock
    feeder: BoundSemanticBlock
    comparison_entry: BoundSemanticBlock


@dataclass(frozen=True, slots=True)
class BoundSemanticStateDag:
    """Stable decision-DAG route rebound to current graph serials."""

    evidence: SemanticStateDagProof
    source: BoundSemanticBlock
    target: BoundSemanticBlock
    entry: BoundSemanticBlock
    path: tuple[BoundSemanticBlock, ...]


@dataclass(frozen=True, slots=True)
class BoundSemanticBootstrap:
    """A bootstrap proof rebound to current graph blocks."""

    evidence: SemanticBootstrapProof
    entry: BoundSemanticBlock
    source: BoundSemanticBlock
    owner: BoundSemanticBlock
    dispatcher: BoundSemanticBlock
    corridor: tuple[BoundSemanticBlock, ...]


@dataclass(frozen=True, slots=True)
class BoundSemanticStatePartition:
    """Partition group rebound to current owner/feeder serials."""

    evidence: SemanticStatePartitionProof
    feeder: BoundSemanticBlock
    owners: tuple[BoundSemanticBlock, ...]


@dataclass(frozen=True, slots=True)
class BoundSemanticRoute:
    """One route proof fully rebound into the current normalized graph."""

    evidence: SemanticRouteProof
    source: BoundSemanticBlock
    destinations: tuple[BoundSemanticRouteDestination, ...]
    source_owner: BoundSemanticBlock | None = None
    state_write_block: BoundSemanticBlock | None = None
    state_transform: BoundSemanticStateTransform | None = None
    state_carrier: BoundSemanticStateCarrier | None = None
    state_partition: BoundSemanticStatePartition | None = None
    state_dag: BoundSemanticStateDag | None = None
    bootstrap: BoundSemanticBootstrap | None = None
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


@dataclass(frozen=True, slots=True)
class CanonicalRouteBindingFailure:
    """Typed first-stage failure for one canonical proof."""

    proof_id: str
    stage: CanonicalRouteBindingStage
    source_anchor_ea: int
    destination_anchor_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.proof_id) is not str or not self.proof_id:
            raise TypeError("binding failure proof_id must be a non-empty exact string")
        if type(self.stage) is not CanonicalRouteBindingStage:
            raise TypeError("binding failure stage must be canonical")
        source_anchor = _native_ea(self.source_anchor_ea, "binding failure source anchor")
        destinations = tuple(_native_ea(item, "binding failure destination anchor") for item in self.destination_anchor_eas)
        object.__setattr__(self, "source_anchor_ea", source_anchor)
        object.__setattr__(self, "destination_anchor_eas", destinations)


@dataclass(frozen=True, slots=True)
class CanonicalRouteBindingResult:
    """Closed transaction-bound result: bound evidence or typed failures."""

    bound_evidence: BoundCanonicalSemanticEvidence | None
    failures: tuple[CanonicalRouteBindingFailure, ...]

    def __post_init__(self) -> None:
        failures = tuple(self.failures)
        if any(type(item) is not CanonicalRouteBindingFailure for item in failures):
            raise TypeError("binding result failures must be typed")
        ordered = tuple(sorted(
            failures,
            key=lambda item: (
                item.proof_id,
                item.stage.value,
                item.source_anchor_ea,
                item.destination_anchor_eas,
            ),
        ))
        if ordered != failures:
            raise ValueError("binding result failures must be deterministic")
        if self.bound_evidence is None:
            if not failures:
                raise ValueError("rejected binding result requires failures")
        else:
            if type(self.bound_evidence) is not BoundCanonicalSemanticEvidence:
                raise TypeError("accepted binding result requires bound evidence")
            if failures:
                raise ValueError("accepted binding result cannot carry failures")
        object.__setattr__(self, "failures", failures)


def _fingerprint_value(value: object) -> object:
    if value is None or type(value) in (bool, int, str, float):
        return value
    if isinstance(value, Enum):
        return ("enum", type(value).__qualname__, value.value)
    if is_dataclass(value):
        return (
            "record", type(value).__qualname__,
            tuple(
                (item.name, _fingerprint_value(getattr(value, item.name)))
                for item in fields(value)
                if not item.name.startswith("_")
            ),
        )
    if isinstance(value, Mapping):
        return (
            "mapping",
            tuple(sorted(
                (_fingerprint_value(key), _fingerprint_value(item))
                for key, item in value.items()
            )),
        )
    if type(value) is tuple:
        return ("tuple", tuple(_fingerprint_value(item) for item in value))
    if type(value) is list:
        return ("list", tuple(_fingerprint_value(item) for item in value))
    if type(value) is frozenset:
        return ("frozenset", tuple(sorted(_fingerprint_value(item) for item in value)))
    if type(value) is set:
        return ("set", tuple(sorted(_fingerprint_value(item) for item in value)))
    raise TypeError(f"unsupported route fingerprint value: {type(value).__name__}")


def _stable_route_proof_payload(proof: SemanticRouteProof) -> object:
    """Serialize only stable proof content for authority identities.

    The top-level IDs and diagnostic provenance are deliberately omitted.  The
    latter may carry a provider fact label, which is useful for diagnostics but
    must never become part of canonical route ownership.
    """

    return _fingerprint_value(
        tuple(
            (item.name, getattr(proof, item.name))
            for item in fields(proof)
            if item.name not in {"proof_id", "atomic_group_id", "diagnostic_provenance"}
        )
    )


def _canonical_route_group_id(
    *,
    native_key: NativePreanalysisKey,
    generation: int,
    proofs: tuple[SemanticRouteProof, ...],
) -> str:
    payload = {
        "native_key": _fingerprint_value(native_key),
        "generation": int(generation),
        "proofs": tuple(
            sorted(
                json.dumps(_stable_route_proof_payload(proof), sort_keys=True, separators=(",", ":"))
                for proof in proofs
            )
        ),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _canonical_route_proof_id(
    *,
    atomic_group_id: str,
    proof: SemanticRouteProof,
) -> str:
    payload = {
        "atomic_group_id": str(atomic_group_id),
        "proof": _stable_route_proof_payload(proof),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def canonical_semantic_evidence_from_proofs(
    native_key: NativePreanalysisKey,
    generation: int,
    proofs: tuple[SemanticRouteProof, ...],
) -> CanonicalSemanticEvidence:
    """Construct canonical evidence and mint all IDs from stable proof content."""
    route_proofs = tuple(proofs)
    group_id = _canonical_route_group_id(
        native_key=native_key,
        generation=generation,
        proofs=route_proofs,
    )
    canonical_proofs = tuple(
        replace(
            proof,
            atomic_group_id=group_id,
            proof_id=_canonical_route_proof_id(
                atomic_group_id=group_id,
                proof=proof,
            ),
        )
        for proof in route_proofs
    )
    return CanonicalSemanticEvidence(
        native_key=native_key,
        generation=generation,
        atomic_group_id=group_id,
        route_proofs=canonical_proofs,
    )


def _validate_content_derived_ids(
    *,
    native_key: NativePreanalysisKey,
    generation: int,
    atomic_group_id: str,
    route_proofs: tuple[SemanticRouteProof, ...],
) -> None:
    """Reject hash-shaped IDs that do not match their immutable content.

    Every canonical evidence identity must be reproducible from proof content.
    """
    expected_group = _canonical_route_group_id(
        native_key=native_key,
        generation=generation,
        proofs=route_proofs,
    )
    if atomic_group_id != expected_group:
        raise SemanticRouteEvidenceRejected(
            "canonical semantic atomic group id is not content-derived"
        )
    for proof in route_proofs:
        if proof.atomic_group_id != expected_group:
            raise SemanticRouteEvidenceRejected(
                "canonical semantic proof group id is not content-derived"
            )
        expected_proof = _canonical_route_proof_id(
            atomic_group_id=expected_group,
            proof=proof,
        )
        if proof.proof_id != expected_proof:
            raise SemanticRouteEvidenceRejected(
                "canonical semantic proof id is not content-derived"
            )


def _materialized_graph_fingerprint(
    graph: FlowGraph, blocks: Mapping[int, BlockSnapshot],
) -> str:
    return portable_graph_fingerprint(graph, blocks=blocks)


def _materialized_graph_fingerprint_values(
    func_ea: int, entry_serial: int, blocks: Mapping[int, BlockSnapshot],
) -> str:
    return portable_graph_fingerprint_values(func_ea, entry_serial, blocks)


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class CanonicalRouteMaterialization:
    """Immutable route-binding input captured once from a live ``FlowGraph``."""

    blocks: Mapping[int, object]
    entry_serial: int
    func_ea: int
    graph_fingerprint: str
    generation: int
    phase: CanonicalRouteAssessmentPhase

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("route materializations are transaction-owned")

    @classmethod
    def capture(
        cls,
        graph: FlowGraph,
        *,
        generation: int,
        phase: CanonicalRouteAssessmentPhase,
    ) -> "CanonicalRouteMaterialization":
        del cls, graph, generation, phase
        raise TypeError("route materialization capture is installed by the authority kernel")

    def __post_init__(self) -> None:
        if type(self.blocks) is not MappingProxyType:
            raise TypeError("route materialization blocks must be immutable")
        if any(type(block) is not BlockSnapshot for block in self.blocks.values()):
            raise TypeError("route materialization blocks must be exact snapshots")
        if type(self.entry_serial) is not int or isinstance(self.entry_serial, bool):
            raise TypeError("route materialization entry must be exact int")
        if type(self.func_ea) is not int or isinstance(self.func_ea, bool) or self.func_ea < 0:
            raise TypeError("route materialization function EA must be exact and non-negative")
        if self.blocks and self.entry_serial not in self.blocks:
            raise ValueError("route materialization entry is outside blocks")
        if self.graph_fingerprint != _materialized_graph_fingerprint_values(
            self.func_ea, self.entry_serial, self.blocks,
        ):
            raise ValueError("route materialization fingerprint does not match its snapshot")
        _validate_materialization_registry(self)

    def __copy__(self) -> "CanonicalRouteMaterialization":
        raise TypeError("route materializations cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> "CanonicalRouteMaterialization":
        del memo
        raise TypeError("route materializations cannot be deep-copied")

    def __reduce__(self) -> object:
        raise TypeError("route materializations cannot be pickled")

    def get_block(self, serial: int) -> object:
        return self.blocks[serial]


def _unique_bound_block(
    graph: FlowGraph,
    identity: StableBlockIdentity,
    anchor_ea: int,
) -> BoundSemanticBlock | None:
    anchor_ea = int(anchor_ea)
    anchor_matches = tuple(
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
    exact_identity_matches = tuple(
        block
        for block in anchor_matches
        if stable_block_identity_from_snapshot(
            block,
            native_key=identity.native_key,
        )
        == identity
    )
    if len(exact_identity_matches) == 1:
        (matched_block,) = exact_identity_matches
    elif exact_identity_matches or len(anchor_matches) != 1:
        return None
    else:
        (matched_block,) = anchor_matches
    return BoundSemanticBlock(
        serial=int(matched_block.serial),
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


def _unique_anchor_block(
    graph: FlowGraph,
    anchor_ea: int,
    *,
    native_key: NativePreanalysisKey,
) -> BoundSemanticBlock | None:
    matches = tuple(
        block
        for block in graph.blocks.values()
        if int(block.start_ea) == int(anchor_ea)
        or any(int(instruction.ea) == int(anchor_ea) for instruction in block.insn_snapshots)
    )
    if len(matches) != 1:
        return None
    block = matches[0]
    identity = stable_block_identity_from_snapshot(
        block,
        native_key=native_key,
    )
    return BoundSemanticBlock(
        serial=int(block.serial),
        identity=identity,
        anchor_ea=int(anchor_ea),
    )


def _instruction_at(block, anchor_ea: int):
    """Return the one portable instruction projected at an exact anchor."""
    matches = tuple(
        instruction
        for instruction in InstructionProjection.from_block(block)
        if int(instruction.attrs.get("ea", -1)) == int(anchor_ea)
    )
    return matches[0] if len(matches) == 1 else None


def _snapshot_at(block, anchor_ea: int):
    matches = tuple(
        instruction
        for instruction in block.insn_snapshots
        if int(instruction.ea) == int(anchor_ea)
    )
    return matches[0] if len(matches) == 1 else None


def _instruction_occurrences(
    block: BlockSnapshot,
    anchor_ea: int | None = None,
) -> tuple[tuple[object, Instruction], ...]:
    """Project each source snapshot once, retaining duplicate-EA occurrence order."""
    return tuple(
        (snapshot, project_instruction(snapshot))
        for snapshot in block.insn_snapshots
        if anchor_ea is None or int(snapshot.ea) == int(anchor_ea)
    )


def _canonical_state_store_matches(
    snapshot,
    instruction: Instruction,
    state_write: SemanticStateWriteProof,
) -> bool:
    """Validate one exact 4-byte STORE through the canonical stack locator."""
    if (
        snapshot.kind is not InsnKind.STORE
        or instruction.operation is not ValueOpKind.STORE
        or state_write.width != 4
        or state_write.state_variable.kind is not StorageIdentityKind.STACK
        or instruction.memory is None
        or int(instruction.memory.width) != 4
    ):
        return False
    _, _, destination_offset = operand_stack_offsets(snapshot)
    if destination_offset != int(state_write.state_variable.offset):
        return False
    value = instruction.memory.value
    if value is None:
        return False
    return (
        value.space is Space.CONST
        and int(value.size) == 4
        and (int(value.offset) & 0xFFFFFFFF)
        == (int(state_write.state_constant) & 0xFFFFFFFF)
    )


def _canonical_state_move_matches(
    snapshot,
    instruction: Instruction,
    state_write: SemanticStateWriteProof,
) -> bool:
    return bool(
        snapshot.kind is InsnKind.MOV
        and instruction.operation is ValueOpKind.MOVE
        and instruction.result is not None
        and storage_identity_from_varnode(instruction.result) == state_write.state_variable
        and int(instruction.result.size) == int(state_write.width)
        and len(instruction.inputs) == 1
        and instruction.inputs[0].space is Space.CONST
        and int(instruction.inputs[0].size) == int(state_write.width)
        and (
            int(instruction.inputs[0].offset)
            & ((1 << (8 * int(state_write.width))) - 1)
        )
        == int(state_write.state_constant)
    )


def _canonical_state_write_matches(
    snapshot,
    instruction: Instruction,
    state_write: SemanticStateWriteProof,
) -> bool:
    return (
        _canonical_state_store_matches(snapshot, instruction, state_write)
        if snapshot.kind is InsnKind.STORE
        else _canonical_state_move_matches(snapshot, instruction, state_write)
    )


def _writes_state_identity(
    snapshot,
    instruction: Instruction,
    state_identity: StorageIdentity,
) -> bool:
    if (
        instruction.result is not None
        and storage_identity_from_varnode(instruction.result) == state_identity
    ):
        return True
    return bool(
        state_identity.kind is StorageIdentityKind.STACK
        and snapshot.kind is InsnKind.STORE
        and instruction.operation is ValueOpKind.STORE
        and operand_stack_offsets(snapshot)[2] == int(state_identity.offset)
    )


def _topology_path(graph: FlowGraph, points: tuple[BoundSemanticBlock, ...]) -> bool:
    """Require a directed, reciprocal edge for each distinct corridor step."""
    for left, right in zip(points, points[1:]):
        if left.serial == right.serial:
            continue
        left_block = graph.get_block(left.serial)
        right_block = graph.get_block(right.serial)
        if left_block is None or right_block is None:
            return False
        if right.serial not in left_block.succs or left.serial not in right_block.preds:
            return False
    return True


def _validate_state_write(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    state_write_block: BoundSemanticBlock,
) -> bool:
    state_write = proof.state_write
    if state_write is None:
        return True
    block = graph.get_block(state_write_block.serial)
    if block is None:
        return False
    claimed_occurrences = _instruction_occurrences(
        block, state_write.instruction_ea
    )
    claimed_writers = tuple(
        (snapshot, instruction)
        for snapshot, instruction in claimed_occurrences
        if _writes_state_identity(snapshot, instruction, state_write.state_variable)
    )
    if len(claimed_writers) != 1:
        return False
    selected_snapshot, selected_instruction = claimed_writers[0]
    if selected_snapshot.kind is InsnKind.STORE:
        store_candidates = tuple(
            (snapshot, instruction)
            for snapshot, instruction in _instruction_occurrences(block)
            if (
                snapshot.kind is InsnKind.STORE
                and _writes_state_identity(
                    snapshot, instruction, state_write.state_variable
                )
            )
        )
        if len(store_candidates) != 1:
            return False
    return _canonical_state_write_matches(
        selected_snapshot, selected_instruction, state_write
    )


def _validate_carrier(
    graph: FlowGraph,
    carrier: BoundSemanticCarrier,
) -> bool:
    """Replay the carrier's definition and every live corridor writer."""
    evidence = carrier.evidence
    block = graph.get_block(carrier.definition.serial)
    if block is None:
        return False
    corridor_serials = {point.serial for point in carrier.corridor}
    permitted = evidence.permitted_write_eas

    def valid_writer(ea: int, instruction) -> bool:
        return (
            instruction.operation is ValueOpKind.MOVE
            and instruction.result is not None
            and storage_identity_from_varnode(instruction.result)
            == evidence.storage_identity
            and int(instruction.result.size) == int(evidence.width)
            and len(instruction.inputs) == 1
            and instruction.inputs[0].space is Space.CONST
            and int(instruction.inputs[0].size) == int(evidence.width)
            and int(instruction.inputs[0].offset) in evidence.state_values
            and int(ea) in permitted
        )

    for serial in corridor_serials:
        corridor_block = graph.get_block(serial)
        if corridor_block is None:
            return False
        for snapshot in corridor_block.insn_snapshots:
            instruction = _instruction_at(corridor_block, snapshot.ea)
            if instruction is None:
                return False
            if instruction.result is None:
                continue
            if storage_identity_from_varnode(instruction.result) != evidence.storage_identity:
                continue
            if snapshot.kind is not InsnKind.MOV or not valid_writer(snapshot.ea, instruction):
                return False

    for permitted_ea in permitted:
        permitted_block = _unique_anchor_block(
            graph,
            permitted_ea,
            native_key=evidence.native_key,
        )
        if permitted_block is None:
            return False
        permitted_instruction = _instruction_at(
            graph.get_block(permitted_block.serial),
            permitted_ea,
        )
        if permitted_instruction is None:
            return False
        permitted_snapshot = _snapshot_at(
            graph.get_block(permitted_block.serial),
            permitted_ea,
        )
        if (
            permitted_snapshot is None
            or permitted_snapshot.kind is not InsnKind.MOV
            or not valid_writer(permitted_ea, permitted_instruction)
        ):
            return False
    for consumer in carrier.consumers:
        consumer_block = graph.get_block(consumer.serial)
        if consumer_block is None:
            return False
        snapshot = _snapshot_at(consumer_block, consumer.anchor_ea)
        instruction = _instruction_at(consumer_block, consumer.anchor_ea)
        if (
            snapshot is None
            or instruction is None
            or not any(
                storage_identity_from_varnode(item) == evidence.storage_identity
                and int(item.size) == int(evidence.width)
                for item in instruction.inputs
            )
        ):
            return False
    return True


def _validate_direct_route(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    source: BoundSemanticBlock,
    destinations: tuple[BoundSemanticRouteDestination, ...],
) -> bool:
    """Replay delivery topology where the producer proved a direct edge."""
    if proof.shape is not SemanticRouteShape.DIRECT:
        return True
    if proof.proof_kind in {
        SemanticRouteProofKind.STATE_TRANSFORM,
        SemanticRouteProofKind.STATE_CARRIER,
        SemanticRouteProofKind.STATE_PARTITION,
        SemanticRouteProofKind.STATE_DAG,
        SemanticRouteProofKind.BOOTSTRAP,
    }:
        return True
    state_write = proof.state_write
    if state_write is None:
        return False
    if (
        proof.proof_kind is not SemanticRouteProofKind.STATE_ASSIGNMENT
        or state_write.delivery_kind is not SemanticStateWriteDeliveryKind.DIRECT
    ):
        # Indirect and terminal-return deliveries have no canonical source ->
        # target edge to replay here; terminal carrier evidence owns that
        # materialization boundary.
        return True
    if len(destinations) != 1:
        return False
    source_block = graph.get_block(source.serial)
    target_serial = destinations[0].block.serial
    target_block = graph.get_block(target_serial)
    return bool(
        source_block is not None
        and target_block is not None
        and tuple(source_block.succs) == (target_serial,)
        and source.serial in target_block.preds
    )


def _validate_predicate_writes(
    graph: FlowGraph,
    predicate: BoundSemanticPredicate,
    state_write: SemanticStateWriteProof | None,
) -> bool:
    """Replay predicate-storage writers independently of carrier storage."""
    evidence = predicate.evidence
    corridor_serials = {point.serial for point in predicate.corridor}
    permitted = set(evidence.permitted_write_eas)
    if state_write is not None and state_write.state_variable == evidence.storage_identity:
        permitted.add(int(state_write.instruction_ea))

    def valid_writer(ea: int, instruction) -> bool:
        return (
            instruction.operation is ValueOpKind.MOVE
            and instruction.result is not None
            and storage_identity_from_varnode(instruction.result) == evidence.storage_identity
            and int(instruction.result.size) == int(evidence.width)
            and len(instruction.inputs) == 1
            and instruction.inputs[0].space is Space.CONST
            and int(instruction.inputs[0].size) == int(evidence.width)
            and int(ea) in permitted
        )

    for serial in corridor_serials:
        block = graph.get_block(serial)
        if block is None:
            return False
        for snapshot in block.insn_snapshots:
            instruction = _instruction_at(block, snapshot.ea)
            if instruction is None:
                return False
            if instruction.result is None:
                continue
            if storage_identity_from_varnode(instruction.result) != evidence.storage_identity:
                continue
            if snapshot.kind is not InsnKind.MOV or not valid_writer(snapshot.ea, instruction):
                return False
    for permitted_ea in permitted:
        block = _unique_anchor_block(graph, permitted_ea, native_key=evidence.native_key)
        if block is None:
            return False
        snapshot = _snapshot_at(graph.get_block(block.serial), permitted_ea)
        instruction = _instruction_at(graph.get_block(block.serial), permitted_ea)
        if (
            snapshot is None
            or instruction is None
            or snapshot.kind is not InsnKind.MOV
            or not valid_writer(permitted_ea, instruction)
        ):
            return False
    return True


def _validate_state_write_corridor(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    state_write_block: BoundSemanticBlock,
) -> bool:
    """Replay every anchored write-to-delivery instruction owned by the proof."""
    state_write = proof.state_write
    if state_write is None:
        return True
    state_block = graph.get_block(state_write_block.serial)
    points = tuple(
        state_write_block
        if state_block is not None
        and any(int(snapshot.ea) == int(ea) for snapshot in state_block.insn_snapshots)
        else _unique_anchor_block(graph, ea, native_key=proof.native_key)
        for ea in state_write.corridor_instruction_eas
    )
    if any(point is None for point in points) or not _topology_path(
        graph,
        tuple(point for point in points if point is not None),
    ):
        return False
    if points[0] is None or points[0].serial != state_write_block.serial:
        return False
    for call_ea in state_write.preserved_call_instruction_eas:
        block = _unique_anchor_block(graph, call_ea, native_key=proof.native_key)
        if block is None:
            return False
        snapshot = _snapshot_at(graph.get_block(block.serial), call_ea)
        instruction = _instruction_at(graph.get_block(block.serial), call_ea)
        if (
            snapshot is None
            or instruction is None
            or snapshot.kind is not InsnKind.CALL
            or instruction.control is None
            or instruction.control.call_kind is None
        ):
            return False
    if state_write.authority_transfer_ea is not None:
        block = _unique_anchor_block(
            graph,
            state_write.authority_transfer_ea,
            native_key=proof.native_key,
        )
        if block is None:
            return False
        instruction = _instruction_at(graph.get_block(block.serial), state_write.authority_transfer_ea)
        expected_transfer = {
            SemanticStateWriteDeliveryKind.DIRECT: ControlTransferKind.GOTO,
            SemanticStateWriteDeliveryKind.INDIRECT: ControlTransferKind.INDIRECT_BRANCH,
            SemanticStateWriteDeliveryKind.CONDITIONAL: ControlTransferKind.CONDITIONAL_BRANCH,
        }[state_write.delivery_kind]
        if (
            instruction is None
            or instruction.control is None
            or instruction.control.transfer is not expected_transfer
        ):
            return False
    return True


def _validate_state_transform(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    transform: BoundSemanticStateTransform,
) -> bool:
    """Replay the exact shared state-carrier prover and bind its path."""
    evidence = transform.evidence
    if (
        transform.owner.identity != evidence.owner_identity
        or transform.source.identity != evidence.source_identity
        or transform.feeder.identity != evidence.feeder_identity
        or transform.comparison_entry.identity != evidence.comparison_entry_identity
        or evidence.state_identity is None
    ):
        return False
    if evidence.state_feeder_identity is None:
        if transform.state_feeder is not None:
            return False
    elif (
        transform.state_feeder is None
        or transform.state_feeder.identity != evidence.state_feeder_identity
    ):
        return False
    bound_points = (
        transform.source,
        transform.feeder,
        *((transform.state_feeder,) if transform.state_feeder is not None else ()),
        transform.comparison_entry,
    )
    if tuple(point.identity for point in evidence.corridor) != tuple(
        point.identity for point in (
            *(transform.source, transform.feeder),
            *((transform.state_feeder,) if transform.state_feeder is not None else ()),
            transform.comparison_entry,
        )
    ):
        return False
    for left, right in zip(bound_points, bound_points[1:]):
        left_block = graph.get_block(left.serial)
        right_block = graph.get_block(right.serial)
        if (
            left_block is None
            or right_block is None
            or right.serial not in left_block.succs
            or left.serial not in right_block.preds
        ):
            return False
    required_comparisons = {int(transform.comparison_entry.serial)}
    replayed = prove_exact_u32_state_transform_feeder(
        graph,
        int(transform.source.serial),
        int(transform.feeder.serial),
        state_var_stkoff=(
            int(evidence.state_identity.offset)
            if evidence.state_identity.kind is StorageIdentityKind.STACK
            else None
        ),
        state_var_reg=(
            int(evidence.state_identity.offset)
            if evidence.state_identity.kind is StorageIdentityKind.REGISTER
            else None
        ),
        required_comparison_serials=frozenset(required_comparisons),
        expected_state=int(evidence.state_constant),
    )
    if replayed is None:
        return False
    return (
        replayed.operation == evidence.operation
        and tuple(replayed.program) == tuple(evidence.program)
        and tuple(replayed.source_bindings) == tuple(evidence.source_bindings)
        and replayed.state_identity == evidence.state_identity
        and int(replayed.state) == int(evidence.state_constant)
        and int(replayed.source_ea) == int(evidence.source_anchor_ea)
        and int(replayed.feeder_ea) == int(evidence.feeder_anchor_ea)
        and int(replayed.comparison_entry_ea)
        == int(evidence.comparison_entry_anchor_ea)
        and replayed.state_feeder_ea == evidence.state_feeder_anchor_ea
    )


def _validate_state_carrier(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    carrier: BoundSemanticStateCarrier,
) -> bool:
    """Replay the one shared CONST32 carrier prover against bound blocks."""
    evidence = carrier.evidence
    if (
        carrier.owner.identity != evidence.owner_identity
        or carrier.source.identity != evidence.source_identity
        or carrier.feeder.identity != evidence.feeder_identity
        or carrier.comparison_entry.identity != evidence.comparison_entry_identity
        or carrier.source.serial != carrier.owner.serial
    ):
        return False
    points = (
        carrier.source,
        carrier.feeder,
        carrier.comparison_entry,
    )
    if tuple(point.identity for point in evidence.corridor) != tuple(
        point.identity for point in points
    ) or not _topology_path(graph, points):
        return False
    replayed = prove_exact_u32_carrier_state_write(
        graph,
        int(carrier.source.serial),
        int(carrier.feeder.serial),
        state_var_stkoff=(
            int(evidence.state_identity.offset)
            if evidence.state_identity.kind is StorageIdentityKind.STACK
            else None
        ),
        state_var_reg=(
            int(evidence.state_identity.offset)
            if evidence.state_identity.kind is StorageIdentityKind.REGISTER
            else None
        ),
        required_comparison_serials=frozenset({int(carrier.comparison_entry.serial)}),
    )
    if replayed is None:
        return False
    return (
        int(replayed.state) == int(evidence.state_constant)
        and replayed.carrier == evidence.carrier
        and replayed.state_identity == evidence.state_identity
        and bool(replayed.requires_feeder_clone) == bool(evidence.requires_feeder_clone)
        and int(replayed.source_serial) == int(carrier.source.serial)
        and int(replayed.feeder_serial) == int(carrier.feeder.serial)
        and int(replayed.comparison_entry_serial) == int(carrier.comparison_entry.serial)
    )


def _validate_state_dag(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    dag: BoundSemanticStateDag,
) -> bool:
    """Replay the stable DAG witness after resolving current snapshot serials."""
    evidence = dag.evidence
    witness = evidence.witness
    if proof.proof_kind is SemanticRouteProofKind.STATE_DAG:
        state_write = proof.state_write
        if (
            state_write is None
            or state_write.identity != evidence.source_identity
            or state_write.instruction_ea != evidence.source_anchor_ea
            or state_write.state_variable != witness.state_identity
            or state_write.state_constant != witness.state_constant
            or state_write.state_constant != proof.destinations[0].state_constant
            or state_write.width != 4
        ):
            return False
    elif proof.proof_kind is SemanticRouteProofKind.BOOTSTRAP:
        bootstrap = proof.bootstrap
        state_write = proof.state_write
        if (
            bootstrap is None
            or state_write is None
            or bootstrap.owner.identity != evidence.source_identity
            or bootstrap.owner.anchor_ea != evidence.source_anchor_ea
            or state_write.state_variable != witness.state_identity
            or state_write.state_constant != witness.state_constant
            or state_write.state_constant != proof.destinations[0].state_constant
            or state_write.width != 4
        ):
            return False
    elif proof.proof_kind is SemanticRouteProofKind.STATE_PARTITION:
        partition = proof.state_partition
        member = (
            None
            if partition is None or proof.source_owner_identity is None
            else next(
                (
                    item
                    for item in partition.members
                    if item.owner_identity == proof.source_owner_identity
                ),
                None,
            )
        )
        if (
            partition is None
            or member is None
            or partition.state_identity != witness.state_identity
            or member.state_constant != witness.state_constant
            or proof.destinations[0].state_constant != witness.state_constant
        ):
            return False
    if dag.source.identity != evidence.source_identity or dag.target.identity != evidence.target_identity:
        return False
    if dag.entry.identity != evidence.entry_identity or dag.entry.anchor_ea != evidence.entry_anchor_ea:
        return False
    if tuple(point.identity for point in evidence.path) != tuple(block.identity for block in dag.path):
        return False
    if not dag.path or dag.path[0].serial != dag.entry.serial:
        return False
    if (
        proof.proof_kind
        in {
            SemanticRouteProofKind.STATE_DAG,
            SemanticRouteProofKind.STATE_PARTITION,
            SemanticRouteProofKind.BOOTSTRAP,
        }
        and dag.source.serial != dag.entry.serial
    ):
        source_block = graph.get_block(int(dag.source.serial))
        entry_block = graph.get_block(int(dag.entry.serial))
        if (
            source_block is None
            or entry_block is None
            or int(dag.entry.serial) not in source_block.succs
            or int(dag.source.serial) not in entry_block.preds
        ):
            return False
    node_serials: dict[StableBlockIdentity, int] = {}
    for comparison in witness.comparisons:
        node = _unique_bound_block(graph, comparison.node.identity, comparison.node.anchor_ea)
        true_target = _unique_bound_block(graph, comparison.true_target.identity, comparison.true_target.anchor_ea)
        false_target = _unique_bound_block(graph, comparison.false_target.identity, comparison.false_target.anchor_ea)
        if node is None or true_target is None or false_target is None:
            return False
        current = current_u32_route_comparison(
            graph,
            int(node.serial),
            expected_identities=frozenset({witness.state_identity}),
        )
        if current is None:
            return False
        current_comparison, current_state_identity, _block_ea, _branch_ea = current
        if (
            current_state_identity != witness.state_identity
            or current_comparison.op != comparison.operation
            or int(current_comparison.const) != int(comparison.constant)
            or int(current_comparison.true_target) != int(true_target.serial)
            or int(current_comparison.false_target) != int(false_target.serial)
        ):
            return False
        node_serials[comparison.node.identity] = int(node.serial)
    nodes: dict[int, RouteComparison] = {}
    for comparison in witness.comparisons:
        node = _unique_bound_block(graph, comparison.node.identity, comparison.node.anchor_ea)
        true_target = _unique_bound_block(graph, comparison.true_target.identity, comparison.true_target.anchor_ea)
        false_target = _unique_bound_block(graph, comparison.false_target.identity, comparison.false_target.anchor_ea)
        if node is None or true_target is None or false_target is None:
            return False
        nodes[int(node.serial)] = RouteComparison(
            serial=int(node.serial),
            op=comparison.operation,
            const=int(comparison.constant),
            true_target=int(true_target.serial),
            false_target=int(false_target.serial),
        )
    aliases: dict[int, int] = {}
    for source_point, target_point in witness.aliases:
        source = _unique_bound_block(graph, source_point.identity, source_point.anchor_ea)
        target = _unique_bound_block(graph, target_point.identity, target_point.anchor_ea)
        if source is None or target is None:
            return False
        if current_u32_route_alias(graph, int(source.serial)) != int(target.serial):
            return False
        aliases[int(source.serial)] = int(target.serial)
    try:
        current_dag = DecisionDag(
            32,
            nodes,
            root=int(dag.entry.serial),
            aliases=aliases,
        )
        if current_dag.route_from(int(dag.entry.serial), int(witness.state_constant)) != int(dag.target.serial):
            return False
    except (TypeError, ValueError, KeyError, OverflowError):
        return False
    for left, right in zip(dag.path, (*dag.path[1:], dag.target)):
        left_block = graph.get_block(int(left.serial))
        right_block = graph.get_block(int(right.serial))
        if (
            left_block is None
            or right_block is None
            or int(right.serial) not in left_block.succs
            or int(left.serial) not in right_block.preds
        ):
            return False
    return True


def _validate_bootstrap(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    bootstrap: BoundSemanticBootstrap,
) -> bool:
    """Replay the entry corridor and every preserved call/effect independently."""
    evidence = bootstrap.evidence
    state_write = proof.state_write
    state_dag = proof.state_dag
    bootstrap_evidence = bootstrap.evidence
    destinations = tuple(proof.destinations)
    if len(destinations) != 1:
        return False
    destination = destinations[0]
    if (
        proof.proof_kind is not SemanticRouteProofKind.BOOTSTRAP
        or proof.source_identity != bootstrap.owner.identity
        or proof.source_anchor_ea != bootstrap.owner.anchor_ea
        or state_write is None
        or state_dag is None
        or state_write != bootstrap_evidence.state_write
        or state_dag != bootstrap_evidence.state_dag
        or state_write.state_variable != state_dag.witness.state_identity
        or state_write.state_constant != state_dag.witness.state_constant
        or state_write.state_constant != bootstrap_evidence.state_dag.witness.state_constant
        or state_write.width != 4
        or state_write.identity != bootstrap.source.identity
        or state_write.instruction_ea != bootstrap_evidence.state_write.instruction_ea
        or state_write.instruction_ea != bootstrap.source.anchor_ea
        or state_dag.source_identity != bootstrap.owner.identity
        or state_dag.source_anchor_ea != bootstrap.owner.anchor_ea
        or state_dag.target_identity != destination.target_identity
        or state_dag.target_anchor_ea != destination.target_anchor_ea
        or destination.state_constant != state_write.state_constant
    ):
        return False
    entry_block = graph.get_block(bootstrap.entry.serial)
    source_block = graph.get_block(bootstrap.source.serial)
    owner_block = graph.get_block(bootstrap.owner.serial)
    dispatcher_block = graph.get_block(bootstrap.dispatcher.serial)
    if (
        entry_block is None
        or source_block is None
        or owner_block is None
        or dispatcher_block is None
        or graph.entry_serial != bootstrap.entry.serial
        or bootstrap.source.serial not in entry_block.succs
        or tuple(int(item) for item in source_block.preds) != (bootstrap.entry.serial,)
        or bootstrap.corridor[0].serial != bootstrap.source.serial
        or bootstrap.corridor[-1].serial != bootstrap.dispatcher.serial
        or bootstrap.owner.serial != bootstrap.corridor[-2].serial
        or not _topology_path(graph, bootstrap.corridor)
        or bootstrap.dispatcher.serial not in owner_block.succs
        or bootstrap.owner.serial not in dispatcher_block.preds
        or bootstrap.owner.identity != evidence.owner.identity
        or bootstrap.source.identity != evidence.source.identity
        or bootstrap.dispatcher.identity != evidence.dispatcher.identity
    ):
        return False
    state_identity = state_write.state_variable
    state_write_ea = int(state_write.instruction_ea)
    preserved = tuple(evidence.preserved_effect_sites)
    observed: list[InstructionEffectSite] = []
    for point in bootstrap.corridor:
        point_block = graph.get_block(point.serial)
        if point_block is None:
            return False
        observed.extend(project_instruction_effect_sites(point_block))
    for corridor_index, point in enumerate(bootstrap.corridor):
        block = graph.get_block(point.serial)
        if block is None:
            return False
        if point.serial != bootstrap.dispatcher.serial and point.serial != bootstrap.source.serial:
            previous = bootstrap.corridor[corridor_index - 1]
            if tuple(int(item) for item in block.preds) != (int(previous.serial),):
                return False
        if point.serial == bootstrap.source.serial:
            source_write_occurrences = tuple(
                (source_snapshot, source_instruction)
                for source_snapshot, source_instruction in _instruction_occurrences(
                    block, state_write_ea
                )
                if _writes_state_identity(
                    source_snapshot, source_instruction, state_identity
                )
            )
            if (
                len(source_write_occurrences) != 1
                or not _canonical_state_write_matches(
                    *source_write_occurrences[0], state_write
                )
            ):
                return False
        block_effect_sites = project_instruction_effect_sites(block)
        for snapshot, instruction in _instruction_occurrences(block):
            instruction_ea = int(instruction.attrs.get("ea", -1))
            if instruction_ea < 0:
                return False
            if point.serial != bootstrap.source.serial:
                if instruction.result is not None and storage_identity_from_varnode(instruction.result) == state_identity:
                    return False
            if (
                state_identity.kind is StorageIdentityKind.STACK
                and instruction_references_stack_identity(
                    instruction, int(state_identity.offset)
                )
            ):
                if point.serial != bootstrap.source.serial or instruction_ea != state_write_ea:
                    return False
                if not _canonical_state_store_matches(snapshot, instruction, state_write):
                    return False
        for snapshot, instruction in _instruction_occurrences(block):
            if _canonical_state_store_matches(snapshot, instruction, state_write):
                if int(snapshot.ea) != state_write_ea:
                    return False
    return tuple(
        sorted(
            observed,
            key=lambda site: (
                site.instruction_ea,
                site.host_instruction_ea,
                site.kind.value,
            ),
        )
    ) == preserved


def _validate_state_partition(
    graph: FlowGraph,
    partition: BoundSemanticStatePartition,
) -> bool:
    """Replay every sibling against one current owner OUT fixpoint."""
    evidence = partition.evidence
    if partition.feeder.identity != evidence.feeder_identity:
        return False
    if evidence.group_id != _canonical_partition_group_id(
        evidence.feeder_identity,
        int(evidence.feeder_instruction_ea),
        evidence.state_identity,
        evidence.members,
    ):
        return False
    by_identity = {member.owner_identity: member for member in evidence.members}
    if len(by_identity) != len(evidence.members):
        return False
    if tuple(owner.identity for owner in partition.owners) != tuple(by_identity):
        return False
    expected_owner_serials = {int(owner.serial) for owner in partition.owners}
    feeder_block = graph.get_block(int(partition.feeder.serial))
    if feeder_block is None or {
        int(serial) for serial in feeder_block.preds
    } != expected_owner_serials:
        return False
    fixpoint = run_snapshot_constant_fixpoint(
        graph,
        int(evidence.state_identity.offset)
        if evidence.state_identity.kind is StorageIdentityKind.STACK
        else -1,
    )
    for owner in partition.owners:
        member = by_identity.get(owner.identity)
        if member is None:
            return False
        witness = StatePartitionMemberWitness(
            owner_serial=int(owner.serial),
            feeder_serial=int(partition.feeder.serial),
            state_identity=evidence.state_identity,
            state_constant=int(member.state_constant),
        )
        if not prove_partitioned_state_member(
            graph,
            witness,
            feeder_instruction_ea=int(evidence.feeder_instruction_ea),
            state_var_stkoff=(
                int(evidence.state_identity.offset)
                if evidence.state_identity.kind is StorageIdentityKind.STACK
                else None
            ),
            state_var_reg=(
                int(evidence.state_identity.offset)
                if evidence.state_identity.kind is StorageIdentityKind.REGISTER
                else None
            ),
            fixpoint=fixpoint,
        ):
            return False
    return True


def _validate_terminal_return_carrier(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    destinations: tuple[BoundSemanticRouteDestination, ...],
) -> bool:
    carrier = proof.terminal_return_carrier
    if carrier is None or len(destinations) != 1:
        return False
    capture = _unique_bound_block(
        graph,
        carrier.capture_identity,
        carrier.request.source_handler_ea,
    )
    terminal = _unique_bound_block(
        graph,
        carrier.terminal_identity,
        carrier.request.terminal_target_ea,
    )
    if capture is None or terminal is None:
        return False
    capture_block = graph.get_block(capture.serial)
    terminal_block = graph.get_block(terminal.serial)
    carrier_snapshot = _snapshot_at(capture_block, carrier.carrier_ea)
    carrier_instruction = _instruction_at(capture_block, carrier.carrier_ea)
    if (
        carrier_snapshot is None
        or carrier_instruction is None
        or carrier_snapshot.kind not in {InsnKind.MOV, InsnKind.XDU, InsnKind.XDS}
        or carrier_instruction.operation is not carrier.operation
        or carrier_instruction.result is None
        or int(carrier_instruction.result.size) != int(carrier.return_width)
    ):
        return False
    source = carrier.source
    source_matches = tuple()
    if source.kind is TerminalReturnCarrierSourceKind.STORAGE_VALUE:
        source_matches = tuple(
            item
            for item in carrier_instruction.inputs
            if storage_identity_from_varnode(item) == source.storage_identity
        )
    elif source.kind is TerminalReturnCarrierSourceKind.ADDRESS_OF_STORAGE:
        address_operand = carrier_snapshot.l
        if address_operand is not None and address_operand.kind is OperandKind.ADDRESS:
            addressed = varnode_from_mop_snapshot(address_operand.sub_l)
            if storage_identity_from_varnode(addressed) == source.storage_identity:
                source_matches = (addressed,)
    elif source.kind is TerminalReturnCarrierSourceKind.CONSTANT:
        source_matches = tuple(
            item
            for item in carrier_instruction.inputs
            if item.space is Space.CONST
            and source.constant is not None
            and int(item.offset) == int(source.constant)
        )
    if not source_matches or int(source_matches[0].size) != int(source.width):
        return False
    return_snapshot = _snapshot_at(terminal_block, carrier.terminal_return_ea)
    return_instruction = _instruction_at(terminal_block, carrier.terminal_return_ea)
    corridor_points = tuple(
        _unique_anchor_block(graph, ea, native_key=proof.native_key)
        for ea in carrier.corridor_instruction_eas
    )
    if any(point is None for point in corridor_points):
        return False
    return bool(
        return_snapshot is not None
        and return_instruction is not None
        and return_snapshot.kind is InsnKind.RET
        and return_instruction.control is not None
        and return_instruction.control.transfer is ControlTransferKind.RETURN
        and _topology_path(
            graph,
            tuple(point for point in corridor_points if point is not None),
        )
    )


def _validate_conditional_route(
    graph: FlowGraph,
    proof: SemanticRouteProof,
    source: BoundSemanticBlock,
    destinations: tuple[BoundSemanticRouteDestination, ...],
    predicate: BoundSemanticPredicate,
    state_write_block: BoundSemanticBlock | None,
    source_owner: BoundSemanticBlock | None,
    carriers: tuple[BoundSemanticCarrier, ...],
) -> bool:
    """Replay the canonical proof against the current portable instruction graph."""
    if proof.shape is not SemanticRouteShape.CONDITIONAL:
        return True
    source_block = graph.get_block(source.serial)
    if source_block is None or len(source_block.succs) != 2:
        return False
    destination_by_role = {item.evidence.role: item for item in destinations}
    if set(destination_by_role) != {
        SemanticEdgeRole.CONDITIONAL_TAKEN,
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
    }:
        return False
    destination_serials = {item.block.serial for item in destinations}
    if set(source_block.succs) != destination_serials:
        return False
    for destination in destinations:
        target_block = graph.get_block(destination.block.serial)
        if target_block is None or source.serial not in target_block.preds:
            return False

    origin_block = graph.get_block(predicate.origin.serial)
    consumer_block = graph.get_block(predicate.consumer.serial)
    if origin_block is None or consumer_block is None:
        return False
    # The producer origin identifies where the predicate proof began, but the
    # consumer is the live route-control instruction that owns target and
    # polarity.  Binding those facts from the origin would splice stale
    # producer semantics onto unrelated source topology.
    branch_snapshot = _snapshot_at(consumer_block, predicate.evidence.consumer.anchor_ea)
    branch = _instruction_at(consumer_block, predicate.evidence.consumer.anchor_ea)
    if (
        branch_snapshot is None
        or branch is None
        or branch_snapshot.kind not in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
        or branch.control is None
        or branch.control.transfer is not ControlTransferKind.CONDITIONAL_BRANCH
        or branch.control.target is None
        or int(branch.control.target) not in destination_serials
        or branch.control.predicate is None
    ):
        return False

    predicate_proof = predicate.evidence
    if predicate_proof.kind is SemanticPredicateKind.STORAGE_EQUALS:
        if branch.control.predicate not in {PredicateKind.EQ, PredicateKind.NE}:
            return False
        if predicate_proof.storage_identity is None or predicate_proof.compare_constant is None:
            return False
        if len(branch.inputs) != 2:
            return False
        identities = tuple(
            item for item in branch.inputs if storage_identity_from_varnode(item) is not None
        )
        constants = tuple(item for item in branch.inputs if item.space is Space.CONST)
        if len(identities) != 1 or len(constants) != 1:
            return False
        storage_operand = identities[0]
        constant_operand = constants[0]
        if (
            storage_identity_from_varnode(storage_operand) != predicate_proof.storage_identity
            or int(storage_operand.size) != int(predicate_proof.width)
            or int(constant_operand.size) != int(predicate_proof.width)
            or int(constant_operand.offset)
            != int(predicate_proof.compare_constant)
        ):
            return False
        expected_target_role = (
            SemanticEdgeRole.CONDITIONAL_TAKEN
            if branch.control.predicate is PredicateKind.EQ
            else SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
        )
        if destination_by_role[expected_target_role].block.serial != int(branch.control.target):
            return False
    elif predicate_proof.kind is SemanticPredicateKind.PRESERVE_LIVE:
        if predicate_proof.true_is_taken is None:
            return False
        expected_role = (
            SemanticEdgeRole.CONDITIONAL_TAKEN
            if predicate_proof.true_is_taken
            else SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
        )
        expected_destination = destination_by_role[expected_role]
        if expected_destination.block.serial != int(branch.control.target):
            return False
    else:
        return False

    if predicate.origin.serial != predicate.consumer.serial:
        # A producer-origin branch may be distinct from the route source, but
        # the live source must still carry the same conditional transfer. This
        # prevents splicing an origin's predicate onto unrelated source edges.
        source_branch_matches = False
        source_block = graph.get_block(source.serial)
        if source_block is None:
            return False
        for snapshot in source_block.insn_snapshots:
            source_branch = _instruction_at(source_block, snapshot.ea)
            if source_branch is None:
                return False
            if (
                source_branch.control is not None
                and source_branch.control.transfer is ControlTransferKind.CONDITIONAL_BRANCH
                and source_branch.control.target == branch.control.target
            ):
                source_branch_matches = True
                break
        if not source_branch_matches:
            return False

    if predicate.consumer.serial != source.serial:
        return False
    if not _topology_path(graph, predicate.corridor):
        return False
    if not _validate_predicate_writes(graph, predicate, proof.state_write):
        return False
    if state_write_block is not None and not _validate_state_write(
        graph,
        proof,
        state_write_block,
    ):
        return False
    if source_owner is not None and state_write_block is not None and source_owner.serial != state_write_block.serial:
        return False
    if any(
        not _validate_carrier(graph, carrier)
        or not _topology_path(graph, carrier.corridor)
        for carrier in carriers
    ):
        return False
    if state_write_block is not None and proof.state_write is not None:
        state_corridor = tuple(
            _unique_anchor_block(
                graph,
                ea,
                native_key=proof.native_key,
            )
            for ea in proof.state_write.corridor_instruction_eas
        )
        if any(item is None for item in state_corridor) or not _topology_path(
            graph,
            tuple(item for item in state_corridor if item is not None),
        ):
            return False
    return True


def _bind_canonical_route(
    graph: FlowGraph | CanonicalRouteMaterialization,
    proof: SemanticRouteProof,
) -> BoundSemanticRoute | CanonicalRouteBindingFailure:
    """Bind one proof once, returning either authority or its typed failure."""

    destinations = tuple(proof.destinations)
    destination_anchors = tuple(int(item.target_anchor_ea) for item in destinations)
    source = _unique_bound_block(graph, proof.source_identity, proof.source_anchor_ea)
    if source is None:
        return CanonicalRouteBindingFailure(
            proof.proof_id, CanonicalRouteBindingStage.SOURCE_IDENTITY,
            proof.source_anchor_ea, destination_anchors,
        )
    bound_destinations = []
    for destination in destinations:
        block = _unique_bound_block(graph, destination.target_identity, destination.target_anchor_ea)
        if block is None:
            return CanonicalRouteBindingFailure(
                proof.proof_id, CanonicalRouteBindingStage.DESTINATION_IDENTITY,
                proof.source_anchor_ea, destination_anchors,
            )
        bound_destinations.append(BoundSemanticRouteDestination(destination, block))

    def failure(stage: CanonicalRouteBindingStage) -> CanonicalRouteBindingFailure:
        return CanonicalRouteBindingFailure(
            proof.proof_id, stage, proof.source_anchor_ea, destination_anchors,
        )

    source_owner = None
    if proof.source_owner_identity is not None:
        source_owner = _unique_bound_block(
            graph, proof.source_owner_identity, int(proof.source_owner_anchor_ea),
        )
        if source_owner is None:
            return failure(CanonicalRouteBindingStage.SUBPROOF_IDENTITY)
    state_write_block = None
    if proof.state_write is not None:
        state_write_block = _unique_bound_block(
            graph, proof.state_write.identity, proof.state_write.instruction_ea,
        )
        if state_write_block is None:
            return failure(CanonicalRouteBindingStage.STATE_WRITE)

    bound_predicate = None
    if proof.predicate is not None:
        predicate_origin = _bound_corridor_point(graph, proof.predicate.origin)
        predicate_consumer = _bound_corridor_point(graph, proof.predicate.consumer)
        predicate_corridor = tuple(
            _bound_corridor_point(graph, point)
            for point in proof.predicate.corridor
        )
        if (
            predicate_origin is None
            or predicate_consumer is None
            or any(block is None for block in predicate_corridor)
        ):
            return failure(CanonicalRouteBindingStage.SUBPROOF_IDENTITY)
        bound_predicate = BoundSemanticPredicate(
            evidence=proof.predicate,
            origin=predicate_origin,
            consumer=predicate_consumer,
            corridor=tuple(predicate_corridor),
        )

    bound_carriers: list[BoundSemanticCarrier] = []
    for carrier in proof.carriers:
        carrier_definition = _bound_corridor_point(graph, carrier.definition)
        carrier_consumers = tuple(
            _bound_corridor_point(graph, consumer)
            for consumer in carrier.consumers
        )
        carrier_corridor = tuple(
            _bound_corridor_point(graph, point) for point in carrier.corridor
        )
        if (
            carrier_definition is None
            or any(block is None for block in carrier_consumers)
            or any(block is None for block in carrier_corridor)
        ):
            return failure(CanonicalRouteBindingStage.SUBPROOF_IDENTITY)
        bound_carriers.append(
            BoundSemanticCarrier(
                evidence=carrier,
                definition=carrier_definition,
                consumers=tuple(carrier_consumers),
                corridor=tuple(carrier_corridor),
            )
        )

    bound_transform = None
    if proof.state_transform is not None:
        transform = proof.state_transform
        owner = _unique_bound_block(graph, transform.owner_identity, transform.owner_anchor_ea)
        source_block = _unique_bound_block(graph, transform.source_identity, transform.source_anchor_ea)
        feeder = _unique_bound_block(graph, transform.feeder_identity, transform.feeder_anchor_ea)
        comparison = _unique_bound_block(graph, transform.comparison_entry_identity, transform.comparison_entry_anchor_ea)
        state_feeder = (
            None if transform.state_feeder_identity is None else _unique_bound_block(
                graph, transform.state_feeder_identity, int(transform.state_feeder_anchor_ea),
            )
        )
        if owner is None or source_block is None or feeder is None or comparison is None or (
            transform.state_feeder_identity is not None and state_feeder is None
        ):
            return failure(CanonicalRouteBindingStage.STATE_TRANSFORM)
        bound_transform = BoundSemanticStateTransform(
            transform, owner, source_block, feeder, comparison, state_feeder,
        )
        if not _validate_state_transform(graph, proof, bound_transform):
            return failure(CanonicalRouteBindingStage.STATE_TRANSFORM)

    bound_state_carrier = None
    if proof.state_carrier is not None:
        carrier = proof.state_carrier
        owner = _unique_bound_block(graph, carrier.owner_identity, carrier.owner_anchor_ea)
        source_block = _unique_bound_block(graph, carrier.source_identity, carrier.source_anchor_ea)
        feeder = _unique_bound_block(graph, carrier.feeder_identity, carrier.feeder_anchor_ea)
        comparison = _unique_bound_block(graph, carrier.comparison_entry_identity, carrier.comparison_entry_anchor_ea)
        if owner is None or source_block is None or feeder is None or comparison is None:
            return failure(CanonicalRouteBindingStage.STATE_CARRIER)
        bound_state_carrier = BoundSemanticStateCarrier(
            carrier, owner, source_block, feeder, comparison,
        )
        if not _validate_state_carrier(graph, proof, bound_state_carrier):
            return failure(CanonicalRouteBindingStage.STATE_CARRIER)

    bound_state_partition = None
    if proof.state_partition is not None:
        partition = proof.state_partition
        feeder = _unique_bound_block(graph, partition.feeder_identity, partition.feeder_anchor_ea)
        owners = tuple(
            _unique_bound_block(graph, member.owner_identity, member.owner_anchor_ea)
            for member in partition.members
        )
        if feeder is None or any(owner is None for owner in owners):
            return failure(CanonicalRouteBindingStage.STATE_PARTITION)
        bound_state_partition = BoundSemanticStatePartition(
            partition, feeder, tuple(owner for owner in owners if owner is not None),
        )
        if not _validate_state_partition(graph, bound_state_partition):
            return failure(CanonicalRouteBindingStage.STATE_PARTITION)

    bound_state_dag = None
    if proof.state_dag is not None:
        dag = proof.state_dag
        dag_source = _unique_bound_block(graph, dag.source_identity, dag.source_anchor_ea)
        dag_target = _unique_bound_block(graph, dag.target_identity, dag.target_anchor_ea)
        dag_entry = _unique_bound_block(graph, dag.entry_identity, dag.entry_anchor_ea)
        dag_path = tuple(_bound_corridor_point(graph, point) for point in dag.path)
        if dag_source is None or dag_target is None or dag_entry is None or any(point is None for point in dag_path):
            return failure(CanonicalRouteBindingStage.STATE_DAG)
        bound_state_dag = BoundSemanticStateDag(
            dag, dag_source, dag_target, dag_entry,
            tuple(point for point in dag_path if point is not None),
        )
        if not _validate_state_dag(graph, proof, bound_state_dag):
            return failure(CanonicalRouteBindingStage.STATE_DAG)

    bound_bootstrap = None
    if proof.bootstrap is not None:
        bootstrap = proof.bootstrap
        entry = _unique_bound_block(graph, bootstrap.entry.identity, bootstrap.entry.anchor_ea)
        bootstrap_source = _unique_bound_block(graph, bootstrap.source.identity, bootstrap.source.anchor_ea)
        owner = _unique_bound_block(graph, bootstrap.owner.identity, bootstrap.owner.anchor_ea)
        dispatcher = _unique_bound_block(graph, bootstrap.dispatcher.identity, bootstrap.dispatcher.anchor_ea)
        corridor = tuple(_bound_corridor_point(graph, point) for point in bootstrap.corridor)
        if entry is None or bootstrap_source is None or owner is None or dispatcher is None or any(point is None for point in corridor):
            return failure(CanonicalRouteBindingStage.BOOTSTRAP)
        bound_bootstrap = BoundSemanticBootstrap(
            bootstrap, entry, bootstrap_source, owner, dispatcher,
            tuple(point for point in corridor if point is not None),
        )
        if not _validate_bootstrap(graph, proof, bound_bootstrap):
            return failure(CanonicalRouteBindingStage.BOOTSTRAP)

    bound_route = BoundSemanticRoute(
        evidence=proof,
        source=source,
        destinations=tuple(bound_destinations),
        source_owner=source_owner,
        state_write_block=state_write_block,
        state_transform=bound_transform,
        state_carrier=bound_state_carrier,
        state_partition=bound_state_partition,
        state_dag=bound_state_dag,
        bootstrap=bound_bootstrap,
        predicate=bound_predicate,
        carriers=tuple(bound_carriers),
    )
    if proof.shape is SemanticRouteShape.CONDITIONAL:
        if bound_predicate is None or not _validate_conditional_route(
            graph,
            proof,
            source,
            tuple(bound_destinations),
            bound_predicate,
            state_write_block,
            source_owner,
            tuple(bound_carriers),
        ):
            return failure(CanonicalRouteBindingStage.CONDITIONAL_ROUTE)
    else:
        if state_write_block is not None:
            if not _validate_state_write(graph, proof, state_write_block):
                return failure(CanonicalRouteBindingStage.STATE_WRITE)
            if not _validate_state_write_corridor(graph, proof, state_write_block):
                return failure(CanonicalRouteBindingStage.STATE_WRITE_CORRIDOR)
        if not _validate_direct_route(
            graph, proof, source, tuple(bound_destinations),
        ):
            return failure(CanonicalRouteBindingStage.DIRECT_ROUTE)
    if proof.proof_kind is SemanticRouteProofKind.TERMINAL_RETURN and not _validate_terminal_return_carrier(
        graph, proof, tuple(bound_destinations),
    ):
        return failure(CanonicalRouteBindingStage.TERMINAL_RETURN)
    return bound_route


def _bind_canonical_semantic_evidence_result(
    graph: FlowGraph | CanonicalRouteMaterialization,
    evidence: CanonicalSemanticEvidence,
) -> CanonicalRouteBindingResult:
    if type(graph) not in (FlowGraph, CanonicalRouteMaterialization):
        raise TypeError("semantic route binding requires a captured graph")
    if type(evidence) is not CanonicalSemanticEvidence:
        raise TypeError("semantic route binding requires canonical evidence")
    try:
        evidence.__post_init__()
    except SemanticRouteEvidenceRejected:
        failures = tuple(
            CanonicalRouteBindingFailure(
                proof.proof_id,
                CanonicalRouteBindingStage.CANONICAL_IDENTITY,
                proof.source_anchor_ea,
                tuple(int(item.target_anchor_ea) for item in proof.destinations),
            )
            for proof in evidence.route_proofs
        )
        return CanonicalRouteBindingResult(None, tuple(sorted(
            failures,
            key=lambda item: (
                item.proof_id,
                item.stage.value,
                item.source_anchor_ea,
                item.destination_anchor_eas,
            ),
        )))
    routes: list[BoundSemanticRoute] = []
    failures: list[CanonicalRouteBindingFailure] = []
    for proof in evidence.route_proofs:
        result = _bind_canonical_route(graph, proof)
        if isinstance(result, BoundSemanticRoute):
            routes.append(result)
        else:
            failures.append(result)
    if failures:
        return CanonicalRouteBindingResult(None, tuple(sorted(failures, key=lambda item: (
            item.proof_id, item.stage.value, item.source_anchor_ea, item.destination_anchor_eas,
        ))))
    return CanonicalRouteBindingResult(
        BoundCanonicalSemanticEvidence(evidence=evidence, routes=tuple(routes)),
        (),
    )


def bind_canonical_semantic_evidence_result(
    graph: FlowGraph | CanonicalRouteMaterialization,
    evidence: CanonicalSemanticEvidence,
) -> CanonicalRouteBindingResult:
    """Return the transaction-owned typed binding result."""

    return _bind_canonical_semantic_evidence_result(graph, evidence)


def bind_canonical_semantic_evidence(
    graph: FlowGraph | CanonicalRouteMaterialization,
    evidence: CanonicalSemanticEvidence,
) -> BoundCanonicalSemanticEvidence | None:
    """Compatibility unwrap for callers that only need accepted evidence."""

    return bind_canonical_semantic_evidence_result(graph, evidence).bound_evidence


def _route_assessment_seal(
    phase: CanonicalRouteAssessmentPhase,
    graph_fingerprint: str,
    generation: int,
    evidence_id: str,
    proof_ids: tuple[str, ...],
    accepted: bool,
    rejection_reason: CanonicalRouteAssessmentRejection | None,
    binding_failures: tuple[CanonicalRouteBindingFailure, ...],
    bound_content_digest: str,
) -> str:
    payload = "\x00".join((
        phase.value, graph_fingerprint, str(generation), evidence_id,
        *proof_ids, "accepted" if accepted else "rejected",
        rejection_reason.value if rejection_reason is not None else "",
        json.dumps(
            _fingerprint_value(binding_failures),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ),
        bound_content_digest,
    ))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class CanonicalRouteAssessment:
    """Closed result of binding one route evidence generation to a graph.

    The public constructor is intentionally unavailable.  Only
    ``assess_canonical_route`` can mint the private authority token, so a
    caller cannot manufacture an accepted route by supplying a boolean or by
    replaying a decoded/ copied record.  Consumers should call
    ``validate_canonical_route_assessment`` before using the result.
    """

    phase: CanonicalRouteAssessmentPhase
    graph_fingerprint: str
    generation: int
    evidence_id: str
    proof_ids: tuple[str, ...]
    evidence: CanonicalSemanticEvidence
    bound_evidence: BoundCanonicalSemanticEvidence | None
    rejection_reason: CanonicalRouteAssessmentRejection | None
    binding_failures: tuple[CanonicalRouteBindingFailure, ...]
    _seal: str = field(default="", repr=False, compare=False)
    _bound_content_digest: str = field(default="", repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("route assessment must be minted by assess_canonical_route")

    def __copy__(self) -> "CanonicalRouteAssessment":
        raise TypeError("route assessments cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> "CanonicalRouteAssessment":
        del memo
        raise TypeError("route assessments cannot be deep-copied")

    def __reduce__(self) -> object:
        raise TypeError("route assessments cannot be pickled")

    def __post_init__(self) -> None:
        if type(self.phase) is not CanonicalRouteAssessmentPhase:
            raise TypeError("route assessment phase must be canonical")
        if type(self.graph_fingerprint) is not str or not self.graph_fingerprint.startswith("sha256:"):
            raise ValueError("route assessment graph fingerprint must be a canonical ID")
        if len(self.graph_fingerprint) != 71:
            raise ValueError("route assessment graph fingerprint must be a SHA-256 ID")
        if type(self.generation) is not int or isinstance(self.generation, bool) or self.generation < 0:
            raise TypeError("route assessment generation must be an exact non-negative int")
        if type(self.evidence_id) is not str or not self.evidence_id:
            raise TypeError("route assessment evidence_id must be a non-empty string")
        if type(self.proof_ids) is not tuple or any(
            type(proof_id) is not str or not proof_id for proof_id in self.proof_ids
        ):
            raise TypeError("route assessment proof_ids must be an exact string tuple")
        if self.proof_ids != tuple(sorted(set(self.proof_ids))):
            raise ValueError("route assessment proof_ids must be sorted and unique")
        if type(self.evidence) is not CanonicalSemanticEvidence:
            raise TypeError("route assessment evidence must be canonical semantic evidence")
        self.evidence.__post_init__()
        expected_proofs = tuple(sorted(proof.proof_id for proof in self.evidence.route_proofs))
        if self.evidence_id != self.evidence.atomic_group_id:
            raise ValueError("route assessment evidence_id does not match atomic group")
        if self.proof_ids != expected_proofs:
            raise ValueError("route assessment proof_ids do not match evidence")
        if type(self.binding_failures) is not tuple or any(
            type(item) is not CanonicalRouteBindingFailure
            for item in self.binding_failures
        ):
            raise TypeError("route assessment binding failures must be typed")
        if self.binding_failures != tuple(sorted(
            self.binding_failures,
            key=lambda item: (
                item.proof_id,
                item.stage.value,
                item.source_anchor_ea,
                item.destination_anchor_eas,
            ),
        )):
            raise ValueError("route assessment binding failures must be deterministic")
        if self.bound_evidence is None:
            if type(self.rejection_reason) is not CanonicalRouteAssessmentRejection:
                raise TypeError("rejected route assessment requires a typed reason")
            if type(self.binding_failures) is not tuple or not self.binding_failures:
                raise ValueError("rejected route assessment requires typed binding failures")
            if any(type(item) is not CanonicalRouteBindingFailure for item in self.binding_failures):
                raise TypeError("route assessment binding failures must be typed")
        else:
            if type(self.bound_evidence) is not BoundCanonicalSemanticEvidence:
                raise TypeError("accepted route assessment requires bound evidence")
            self.bound_evidence.evidence.__post_init__()
            if self.bound_evidence.evidence != self.evidence:
                raise ValueError("bound route assessment evidence does not match source evidence")
            if self.rejection_reason is not None:
                raise ValueError("accepted route assessment cannot carry a rejection reason")
            if self.binding_failures:
                raise ValueError("accepted route assessment cannot carry binding failures")
            _validate_bound_route_content(self.bound_evidence, self.evidence)
        expected_bound_digest = _bound_content_digest(self.bound_evidence)
        if self._bound_content_digest != expected_bound_digest:
            raise ValueError("route assessment bound content seal mismatch")
        expected_seal = _route_assessment_seal(
            self.phase, self.graph_fingerprint, self.generation,
            self.evidence_id, self.proof_ids, self.bound_evidence is not None,
            self.rejection_reason, self.binding_failures, expected_bound_digest,
        )
        if self._seal != expected_seal:
            raise ValueError("route assessment seal does not match its immutable facts")
        _validate_assessment_registry(self)

    @property
    def accepted(self) -> bool:
        """Derived status; callers cannot provide or override this verdict."""

        return self.bound_evidence is not None

    @property
    def rejected(self) -> bool:
        return self.bound_evidence is None

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return (self.evidence_id,)

    @property
    def bound_content_digest(self) -> str:
        """Digest of the exact rebound route/block/endpoint content."""

        return self._bound_content_digest


def _bound_content_digest(bound: BoundCanonicalSemanticEvidence | None) -> str:
    if bound is None:
        return "sha256:" + "0" * 64
    payload = _fingerprint_value(bound)
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_bound_route_content(
    bound: BoundCanonicalSemanticEvidence,
    evidence: CanonicalSemanticEvidence,
) -> None:
    def validate_block(block: BoundSemanticBlock) -> None:
        if type(block) is not BoundSemanticBlock:
            raise TypeError("bound route block must be exact")
        if type(block.serial) is not int or isinstance(block.serial, bool) or block.serial < 0:
            raise ValueError("bound route serial must be exact and non-negative")
        if type(block.identity) is not StableBlockIdentity:
            raise TypeError("bound route identity must be stable")
        if type(block.anchor_ea) is not int or isinstance(block.anchor_ea, bool):
            raise TypeError("bound route anchor must be exact int")
        if not block.identity.native_ranges.contains(block.anchor_ea):
            raise ValueError("bound route anchor is outside its identity")

    if type(bound) is not BoundCanonicalSemanticEvidence:
        raise TypeError("bound route evidence must be exact")
    if type(bound.evidence) is not CanonicalSemanticEvidence:
        raise TypeError("bound route canonical evidence must be exact")
    if type(bound.routes) is not tuple:
        raise TypeError("bound route rows must be an exact tuple")
    if bound.evidence != evidence or len(bound.routes) != len(evidence.route_proofs):
        raise ValueError("bound route evidence does not exactly match canonical evidence")
    for route, proof in zip(bound.routes, evidence.route_proofs):
        if type(route) is not BoundSemanticRoute:
            raise TypeError("bound route must be exact")
        if type(route.evidence) is not SemanticRouteProof:
            raise TypeError("bound route proof must be exact")
        if type(route.destinations) is not tuple:
            raise TypeError("bound route destinations must be an exact tuple")
        if type(route.carriers) is not tuple:
            raise TypeError("bound route carriers must be an exact tuple")
        validate_block(route.source)
        for destination in route.destinations:
            if type(destination) is not BoundSemanticRouteDestination:
                raise TypeError("bound route destination must be exact")
            validate_block(destination.block)
        if route.source_owner is not None:
            validate_block(route.source_owner)
        if route.state_write_block is not None:
            validate_block(route.state_write_block)
        if route.predicate is not None:
            if type(route.predicate) is not BoundSemanticPredicate:
                raise TypeError("bound route predicate must be exact")
            if type(route.predicate.corridor) is not tuple:
                raise TypeError("bound route predicate corridor must be an exact tuple")
            validate_block(route.predicate.origin)
            validate_block(route.predicate.consumer)
            for block in route.predicate.corridor:
                validate_block(block)
        for carrier in route.carriers:
            if type(carrier) is not BoundSemanticCarrier:
                raise TypeError("bound route carrier must be exact")
            if type(carrier.consumers) is not tuple or type(carrier.corridor) is not tuple:
                raise TypeError("bound route carrier rows must be exact tuples")
            validate_block(carrier.definition)
            for block in (*carrier.consumers, *carrier.corridor):
                validate_block(block)
        if route.evidence != proof:
            raise ValueError("bound route proof mismatch")
        if route.source.identity != proof.source_identity or route.source.anchor_ea != proof.source_anchor_ea:
            raise ValueError("bound route source mismatch")
        if len(route.destinations) != len(proof.destinations):
            raise ValueError("bound route destination count mismatch")
        for bound_destination, destination in zip(route.destinations, proof.destinations):
            if (
                bound_destination.evidence != destination
                or bound_destination.block.identity != destination.target_identity
                or bound_destination.block.anchor_ea != destination.target_anchor_ea
            ):
                raise ValueError("bound route destination mismatch")
        if proof.source_owner_identity is None:
            if route.source_owner is not None:
                raise ValueError("bound route has an unexpected source owner")
        elif (
            route.source_owner is None
            or route.source_owner.identity != proof.source_owner_identity
            or route.source_owner.anchor_ea != proof.source_owner_anchor_ea
        ):
            raise ValueError("bound route source owner mismatch")
        if proof.state_write is None:
            if route.state_write_block is not None:
                raise ValueError("bound route has an unexpected state-write block")
        elif (
            route.state_write_block is None
            or route.state_write_block.identity != proof.state_write.identity
            or route.state_write_block.anchor_ea != proof.state_write.instruction_ea
        ):
            raise ValueError("bound route state-write mismatch")
        if proof.state_transform is None:
            if route.state_transform is not None:
                raise ValueError("bound route has an unexpected state transform")
        elif (
            route.state_transform is None
            or route.state_transform.evidence != proof.state_transform
            or route.state_transform.owner.identity != proof.state_transform.owner_identity
            or route.state_transform.source.identity != proof.state_transform.source_identity
            or route.state_transform.feeder.identity != proof.state_transform.feeder_identity
            or route.state_transform.comparison_entry.identity
            != proof.state_transform.comparison_entry_identity
        ):
            raise ValueError("bound route state-transform mismatch")
        if proof.predicate is None:
            if route.predicate is not None:
                raise ValueError("bound route has an unexpected predicate")
        elif route.predicate is None or route.predicate.evidence != proof.predicate:
            raise ValueError("bound route predicate mismatch")
        if tuple(item.evidence for item in route.carriers) != proof.carriers:
            raise ValueError("bound route carrier mismatch")


def validate_bound_canonical_semantic_evidence(
    bound: BoundCanonicalSemanticEvidence,
    evidence: CanonicalSemanticEvidence,
) -> None:
    """Public validation boundary for canonical bound route evidence."""
    _validate_bound_route_content(bound, evidence)


def _install_closed_route_authority() -> tuple[object, ...]:
    import weakref

    materializations: dict[int, tuple[weakref.ReferenceType[object], object]] = {}
    assessments: dict[int, tuple[weakref.ReferenceType[object], object]] = {}

    def expected_materialization(value: CanonicalRouteMaterialization) -> object:
        return (
            value.entry_serial, value.func_ea, value.graph_fingerprint,
            value.generation, value.phase,
        )

    def expected_assessment(value: CanonicalRouteAssessment) -> object:
        return (
            value.phase, value.graph_fingerprint, value.generation,
            value.evidence_id, _fingerprint_value(value.proof_ids),
            _fingerprint_value(value.evidence),
            _fingerprint_value(value.bound_evidence), value.rejection_reason,
            _fingerprint_value(value.binding_failures),
            value._seal, value._bound_content_digest,
        )

    def register(
        registry: dict[int, tuple[weakref.ReferenceType[object], object]],
        value: object,
        expected: object,
    ) -> None:
        ident = id(value)

        def remove(reference: weakref.ReferenceType[object]) -> None:
            record = registry.get(ident)
            if record is not None and record[0] is reference:
                registry.pop(ident, None)

        registry[ident] = (weakref.ref(value, remove), expected)

    def validate(
        registry: dict[int, tuple[weakref.ReferenceType[object], object]],
        value: object,
        expected: object,
        description: str,
    ) -> None:
        record = registry.get(id(value))
        if record is None or record[0]() is not value:
            raise TypeError(f"{description} is not a registered result")
        if record[1] != expected:
            raise ValueError(f"{description} changed after capture")

    def capture(
        cls: type[CanonicalRouteMaterialization],
        graph: FlowGraph,
        *,
        generation: int,
        phase: CanonicalRouteAssessmentPhase,
    ) -> CanonicalRouteMaterialization:
        if type(graph) is not FlowGraph:
            raise TypeError("route materialization requires an exact FlowGraph")
        if type(generation) is not int or isinstance(generation, bool) or generation < 0:
            raise TypeError("route materialization generation must be exact and non-negative")
        if type(phase) is not CanonicalRouteAssessmentPhase:
            raise TypeError("route materialization phase must be canonical")
        cached_blocks = dict(graph.blocks)
        value = object.__new__(cls)
        object.__setattr__(value, "blocks", MappingProxyType(cached_blocks))
        object.__setattr__(value, "entry_serial", graph.entry_serial)
        object.__setattr__(value, "func_ea", graph.func_ea)
        object.__setattr__(
            value, "graph_fingerprint",
            _materialized_graph_fingerprint(graph, cached_blocks),
        )
        object.__setattr__(value, "generation", generation)
        object.__setattr__(value, "phase", phase)
        register(materializations, value, expected_materialization(value))
        cls.__post_init__(value)
        return value

    def validate_materialization(value: object) -> CanonicalRouteMaterialization:
        if type(value) is not CanonicalRouteMaterialization:
            raise TypeError("route materialization must be CanonicalRouteMaterialization")
        # Shape and fingerprint checks remain on the nominal class boundary.
        CanonicalRouteMaterialization.__post_init__(value)
        validate(
            materializations, value, expected_materialization(value),
            "route materialization",
        )
        return value

    def assess(
        materialization: CanonicalRouteMaterialization,
        evidence: CanonicalSemanticEvidence,
    ) -> CanonicalRouteAssessment:
        validate_materialization(materialization)
        if type(evidence) is not CanonicalSemanticEvidence:
            raise TypeError("route assessment requires canonical semantic evidence")
        evidence.__post_init__()
        binding_result = _bind_canonical_semantic_evidence_result(materialization, evidence)
        bound = binding_result.bound_evidence
        binding_failures = binding_result.failures
        rejection_reason = (
            None if bound is not None
            else CanonicalRouteAssessmentRejection.ROUTE_BINDING_FAILED
        )
        proof_ids = tuple(sorted(proof.proof_id for proof in evidence.route_proofs))
        bound_digest = _bound_content_digest(bound)
        value = object.__new__(CanonicalRouteAssessment)
        for name, item in {
            "phase": materialization.phase,
            "graph_fingerprint": materialization.graph_fingerprint,
            "generation": materialization.generation,
            "evidence_id": evidence.atomic_group_id,
            "proof_ids": proof_ids,
            "evidence": evidence,
            "bound_evidence": bound,
            "rejection_reason": rejection_reason,
            "binding_failures": binding_failures,
            "_seal": _route_assessment_seal(
                materialization.phase, materialization.graph_fingerprint,
                materialization.generation, evidence.atomic_group_id, proof_ids,
                bound is not None, rejection_reason, binding_failures,
                bound_digest,
            ),
            "_bound_content_digest": bound_digest,
        }.items():
            object.__setattr__(value, name, item)
        register(assessments, value, expected_assessment(value))
        CanonicalRouteAssessment.__post_init__(value)
        return value

    def validate_assessment(value: object) -> CanonicalRouteAssessment:
        if type(value) is not CanonicalRouteAssessment:
            raise TypeError("route assessment must be CanonicalRouteAssessment")
        CanonicalRouteAssessment.__post_init__(value)
        validate(assessments, value, expected_assessment(value), "route assessment")
        return value

    def validate_materialization_registry(value: object) -> None:
        validate(
            materializations, value, expected_materialization(value),
            "route materialization",
        )

    def validate_assessment_registry(value: object) -> None:
        validate(assessments, value, expected_assessment(value), "route assessment")

    return (
        capture, assess, validate_materialization, validate_assessment,
        validate_materialization_registry, validate_assessment_registry,
    )


(
    _closed_capture, _closed_assess, _closed_validate_materialization,
    _closed_validate_assessment, _closed_validate_materialization_registry,
    _closed_validate_assessment_registry,
) = _install_closed_route_authority()
CanonicalRouteMaterialization.capture = classmethod(_closed_capture)
assess_canonical_route = _closed_assess
validate_canonical_route_materialization = _closed_validate_materialization
validate_canonical_route_assessment = _closed_validate_assessment
_validate_materialization_registry = _closed_validate_materialization_registry
_validate_assessment_registry = _closed_validate_assessment_registry


# The authority transaction needs an immutable graph snapshot, but must not
# import the route-assessment lifecycle DTO merely to name its capture phase.
# Keep that translation inside the analysis layer: the three factories expose
# capture intent without making assessment phases part of transaction authority.
def capture_source_route_materialization(
    graph: FlowGraph, *, generation: int,
) -> CanonicalRouteMaterialization:
    return CanonicalRouteMaterialization.capture(
        graph, generation=generation, phase=CanonicalRouteAssessmentPhase.SOURCE,
    )


def capture_projected_route_materialization(
    graph: FlowGraph, *, generation: int,
) -> CanonicalRouteMaterialization:
    return CanonicalRouteMaterialization.capture(
        graph, generation=generation, phase=CanonicalRouteAssessmentPhase.PROJECTED,
    )


def capture_observed_route_materialization(
    graph: FlowGraph, *, generation: int,
) -> CanonicalRouteMaterialization:
    return CanonicalRouteMaterialization.capture(
        graph, generation=generation, phase=CanonicalRouteAssessmentPhase.OBSERVED,
    )
del _closed_capture, _closed_assess, _closed_validate_materialization
del _closed_validate_assessment, _closed_validate_materialization_registry
del _closed_validate_assessment_registry, _install_closed_route_authority


__all__ = [
    "BoundCanonicalSemanticEvidence",
    "BoundSemanticCarrier",
    "BoundSemanticBlock",
    "BoundSemanticPredicate",
    "BoundSemanticRoute",
    "BoundSemanticRouteDestination",
    "BoundSemanticStateTransform",
    "BoundSemanticStateCarrier",
    "BoundSemanticBootstrap",
    "CanonicalSemanticEvidence",
    "CanonicalSemanticEvidenceProductionContext",
    "CanonicalSemanticEvidenceProductionAbstention",
    "CanonicalSemanticEvidenceProductionFactCoordinate",
    "CanonicalSemanticEvidenceProductionReason",
    "CanonicalSemanticEvidenceProductionResult",
    "CanonicalSemanticEvidenceProductionStage",
    "canonical_semantic_evidence_from_proofs",
    "build_canonical_semantic_evidence",
    "CanonicalRouteMaterialization",
    "capture_source_route_materialization",
    "capture_projected_route_materialization",
    "capture_observed_route_materialization",
    "CanonicalRouteAssessment",
    "CanonicalRouteAssessmentPhase",
    "CanonicalRouteAssessmentRejection",
    "CanonicalRouteBindingStage",
    "CanonicalRouteBindingFailure",
    "CanonicalRouteBindingResult",
    "validate_bound_canonical_semantic_evidence",
    "validate_canonical_route_materialization",
    "validate_canonical_route_assessment",
    "SemanticCarrierProof",
    "SemanticBootstrapProof",
    "SemanticCorridorPoint",
    "SemanticPredicateKind",
    "SemanticPredicateProof",
    "SemanticRouteDestination",
    "SemanticRouteEvidenceRejected",
    "SemanticRouteProof",
    "SemanticRouteFact",
    "SemanticRouteFactKind",
    "SemanticBootstrapRouteWitness",
    "SemanticRouteProofKind",
    "SemanticRouteShape",
    "SemanticStateWriteProof",
    "SemanticStateTransformProof",
    "SemanticStateCarrierProof",
    "SemanticStateWriteDeliveryKind",
    "bind_canonical_semantic_evidence",
    "bind_canonical_semantic_evidence_result",
    "assess_canonical_route",
    "validate_canonical_route_assessment",
    "canonical_terminal_state_targets",
    "semantic_route_proof_reaches_consumer",
]
