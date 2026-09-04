"""Closed, portable semantic-authority records for unflatten planning.

This module deliberately contains no evaluator, graph traversal, hashing, or
live SDK object.  It is the immutable vocabulary shared by the producer and
the later transaction authority implementation.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field as dataclass_field, fields, is_dataclass
from enum import Enum
import hashlib
import math
import re
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    BoundCanonicalSemanticEvidence,
)
from d810.analyses.control_flow.logical_route_endpoint import (
    is_exact_logical_function_exit_inventory_row_shape,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import NativeEaInterval, NativeEaIntervalSet, StableBlockIdentity
from d810.core.typing import Literal, Protocol, TypeAlias, runtime_checkable
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.ir.maturity import MaturityEnvelope
from d810.ir.storage_identity import StorageIdentity
from d810.transforms.patch_binding import (
    BoundPatchPlan,
    ObservedPatchBinding,
    validate_bound_patch_plan,
    validate_observed_patch_binding,
)
from d810.transforms.cfg_transaction import (
    CfgBlockRef,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
    PatchStepKind,
    TransactionAttemptId,
)
from .ids import (
    _occurrence_stamp,
    _subject_id_from_record,
    _validate_id,
    authority_id,
    bound_unflatten_binding_id,
    canonical_bytes,
    validate_canonical_roundtrip,
    case_id,
    claim_id,
    evidence_id,
    justification_id,
    receipt_id,
    semantic_graph_inventory_digest,
    route_realization_id,
    source_route_authority_id,
    projected_route_realization_row_id,
    projected_route_realization_id,
    raw_effect_gate_phase_fact_id,
    exact_effect_binding_result_id,
    local_alias_binding_result_id,
    projected_effect_site_result_id,
    projected_terminal_site_result_id,
    projected_semantic_site_phase_result_id,
    projected_route_site_preservation_id,
    patch_step_fact_id as _canonical_patch_step_fact_id,
    derived_effect_gate_fact_id,
    cloned_semantic_observation_digest,
    cloned_semantic_instruction_origin_id,
    cloned_semantic_prefix_id,
    CLONED_SEMANTIC_OBSERVATION_SCHEMA,
    CLONED_SEMANTIC_ORIGIN_SCHEMA,
    CLONED_SEMANTIC_PREFIX_SCHEMA,
)
from .canonical_session import (
    active_canonical_session,
    record_inventory_seal_check,
    record_inventory_seal_mint,
)
from .legacy_keys import LEGACY_UNFLATTEN_KEYS
from .gates import GenericCfgGateFacts


_BADADDR = 0xFFFFFFFFFFFFFFFF
_OBLIGATION_INDEX_TOKEN = object()
_SHA1_RE = re.compile(r"^[0-9a-f]{16}$")
_CFG_REF_TYPES = (NativeBlockRef, LogicalBlockRef, PlanBlockRef)
_AUTHORITY_REF_TYPES = (NativeBlockRef, LogicalBlockRef)




def _id(value: object, label: str) -> str:
    return _validate_id(value, label)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    return value


def _ea(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if not 0 <= value < _BADADDR:
        raise ValueError(f"{label} must be a native EA")
    return value


def _generation(value: object, label: str = "generation") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must not be negative")
    return value


def _nonnegative(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if value < 0:
        raise ValueError(f"{label} must not be negative")
    return value


def _tuple(values: Iterable[object], label: str, *, sort: bool = False) -> tuple:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{label} must be a tuple of values")
    try:
        result = tuple(values)
    except TypeError as exc:
        raise TypeError(f"{label} must be iterable") from exc
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    if sort:
        result = tuple(sorted(result, key=_structural_key))
    return result


def _paired_tuples(
    left_values: Iterable[object],
    right_values: Iterable[object],
    left_label: str,
    right_label: str,
) -> tuple[tuple[object, object], ...]:
    """Normalize parallel fields without losing their association."""

    left = tuple(left_values)
    right = tuple(right_values)
    if len(left) != len(right):
        raise ValueError(f"{left_label} and {right_label} must have equal length")
    if len(set(left)) != len(left):
        raise ValueError(f"{left_label} must not contain duplicates")
    return tuple(sorted(zip(left, right), key=lambda pair: _structural_key(pair[0])))


def _structural_key(value: object):
    """Return a durable key for canonical unordered model collections."""

    if value is None:
        return ("none",)
    if isinstance(value, Enum):
        return ("enum", value.__class__.__qualname__, value.value)
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, int):
        return ("int", value)
    if type(value) is bytes:
        return ("bytes", value.hex())
    if type(value) is NativeBlockRef:
        identity = value.identity
        return (
            "native",
            identity.native_key.to_json(),
            tuple(sorted(identity.exact_instruction_eas)),
            tuple((item.start_ea, item.end_ea) for item in identity.native_ranges.intervals),
        )
    if type(value) is LogicalBlockRef:
        return ("logical", value.session_id, value.proxy_token, value.version)
    if type(value) is PlanBlockRef:
        return ("plan", value.plan_id, value.local_block_id)
    if type(value) is SemanticSubjectRef:
        return ("subject", value.subject_id)
    if type(value) in (
        RetiredDispatcherInfrastructureClaim,
        DetachedDeadHandlerComponentClaim,
        EquivalentSemanticRouteClaim,
        ExactInfeasibleEffectClaim,
        LocalAliasEffectScalarizationClaim,
        TerminalCycleBreakClaim,
    ):
        return ("claim", value.claim_id)
    if type(value) is EntryEndpointLivenessAllowance:
        return ("entry_endpoint_liveness", value.allowance_id)
    if type(value) is AuthoritativeHandlerInput:
        return ("handler", _structural_key(value.block_ref), value.anchor_ea)
    if isinstance(value, tuple):
        return ("tuple", tuple(_structural_key(item) for item in value))
    if is_dataclass(value):
        return (
            "dataclass",
            value.__class__.__qualname__,
            tuple((field.name, _structural_key(getattr(value, field.name))) for field in fields(value)),
        )
    raise TypeError(f"no durable canonical key for {type(value).__name__}")


def _enum(value: object, cls: type[Enum], label: str):
    if not isinstance(value, cls):
        raise TypeError(f"{label} must be a {cls.__name__}")
    return value


def _cfg_ref(value: object, label: str = "block_ref") -> CfgBlockRef:
    if type(value) not in _CFG_REF_TYPES:
        raise TypeError(f"{label} must be a CfgBlockRef")
    return value


def _canonical_cfg_ref_tuple(
    values: Iterable[object], label: str,
) -> tuple[CfgBlockRef, ...]:
    refs = tuple(values)
    if len(set(refs)) != len(refs):
        raise ValueError(f"{label} must not contain duplicates")
    for ref in refs:
        _cfg_ref(ref, f"{label} item")
    return tuple(sorted(refs, key=canonical_bytes))


def _canonical_source_coordinates(
    values: Iterable[object],
) -> tuple[tuple[CfgBlockRef, int], ...]:
    coordinates = tuple(values)
    for coordinate in coordinates:
        if type(coordinate) is not tuple or len(coordinate) != 2:
            raise TypeError("source coordinates must contain (CfgBlockRef, serial) pairs")
        ref, serial = coordinate
        _cfg_ref(ref, "source coordinate reference")
        _nonnegative(serial, "source coordinate serial")
    return tuple(sorted(coordinates, key=canonical_bytes))


def _authority_ref(value: object, label: str = "block_ref") -> NativeBlockRef | LogicalBlockRef:
    if type(value) not in _AUTHORITY_REF_TYPES:
        raise TypeError(f"{label} must be a NativeBlockRef or LogicalBlockRef")
    return value


def _reject_site_record_copy(self, *args: object, **kwargs: object) -> None:
    del self, args, kwargs
    raise TypeError("semantic site records are binder-owned")


class UnflattenAuthorityPhase(str, Enum):
    PRODUCER_FORECAST = "producer_forecast"
    PROJECTED_PREFLIGHT = "projected_preflight"
    OBSERVED_POST_APPLY = "observed_post_apply"


class SemanticSubjectKind(str, Enum):
    BLOCK = "block"
    EDGE = "edge"
    ROUTE = "route"
    EFFECT = "effect"
    HANDLER = "handler"
    TERMINAL = "terminal"
    VALUE_FLOW = "value_flow"
    CORRIDOR = "corridor"


class SemanticSubjectRole(str, Enum):
    # The sole physical source-block subject.  Structural loss is classified
    # here, once per catalog identity; the remaining block roles are semantic
    # views and must not create competing loss ledgers.
    SOURCE_CATALOG_BLOCK = "source_catalog_block"
    SOURCE_LOGICAL_EXIT = "source_logical_exit"
    SOURCE_ENTRY = "source_entry"
    DISPATCHER_ENTRY = "dispatcher_entry"
    DISPATCHER_INFRASTRUCTURE = "dispatcher_infrastructure"
    SEMANTIC_ROUTE_SOURCE = "semantic_route_source"
    SEMANTIC_ROUTE_DESTINATION = "semantic_route_destination"
    SEMANTIC_DAG_ENDPOINT = "semantic_dag_endpoint"
    EXACT_EFFECT_SOURCE = "exact_effect_source"
    EXACT_EFFECT_PREDICATE = "exact_effect_predicate"
    EXACT_EFFECT_SELECTED_TARGET = "exact_effect_selected_target"
    EXACT_EFFECT_DISCARDED_OWNER = "exact_effect_discarded_owner"
    DEFAULT_GAP_INFEASIBLE_RESIDUAL = "default_gap_infeasible_residual"
    EFFECT_SITE = "effect_site"
    AUTHORITATIVE_HANDLER = "authoritative_handler"
    TERMINAL_SITE = "terminal_site"
    NON_STATE_VALUE_FLOW = "non_state_value_flow"
    DISPATCHER_CORRIDOR = "dispatcher_corridor"
    PLANNED_HELPER = "planned_helper"
    DETACHED_DEAD_HANDLER_COMPONENT = "detached_dead_handler_component"


# Canonical subject vocabulary for semantic CFG topology.  Every producer and
# consumer of subject-level topology must use this same closed role set.
TOPOLOGY_SUBJECT_ROLES = frozenset({
    SemanticSubjectRole.SOURCE_ENTRY,
    SemanticSubjectRole.DISPATCHER_ENTRY,
    SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
    SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
    SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
    SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT,
    SemanticSubjectRole.EXACT_EFFECT_SOURCE,
    SemanticSubjectRole.EXACT_EFFECT_PREDICATE,
    SemanticSubjectRole.EXACT_EFFECT_SELECTED_TARGET,
    SemanticSubjectRole.EXACT_EFFECT_DISCARDED_OWNER,
    SemanticSubjectRole.AUTHORITATIVE_HANDLER,
    SemanticSubjectRole.PLANNED_HELPER,
})


class SafetyDimension(str, Enum):
    STRUCTURAL_ACCOUNTING = "structural_accounting"
    ROUTE_EQUIVALENCE = "route_equivalence"
    EFFECT_PRESERVATION = "effect_preservation"
    ENTRY_REACHABILITY = "entry_reachability"
    HANDLER_REACHABILITY = "handler_reachability"
    TERMINAL_REACHABILITY = "terminal_reachability"
    USE_DEF_INTEGRITY = "use_def_integrity"
    CORRIDOR_COVERAGE = "corridor_coverage"
    TOPOLOGY_INTEGRITY = "topology_integrity"
    IDENTITY_BINDING = "identity_binding"


class EvidencePolarity(str, Enum):
    SUPPORTS = "supports"
    REFUTES = "refutes"


class ObligationState(str, Enum):
    UNPROVEN = "unproven"
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    INCONSISTENT = "inconsistent"


class SemanticLossKind(str, Enum):
    """Closed classifications for source-indexed semantic loss rows."""

    RETIRED_DISPATCHER_INFRASTRUCTURE = "retired_dispatcher_infrastructure"
    EQUIVALENT_SEMANTIC_ROUTE = "equivalent_semantic_route"
    EXACT_INFEASIBLE_EFFECT = "exact_infeasible_effect"
    TERMINAL_CYCLE_BREAK = "terminal_cycle_break"
    LOCAL_ALIAS_SCALARIZATION = "local_alias_scalarization"
    DETACHED_DEAD_HANDLER_COMPONENT = "detached_dead_handler_component"
    COMPOSITE_ALLOWED = "composite_allowed"
    UNCLASSIFIED = "unclassified"
    CONFLICTING = "conflicting"


class SubjectBindingStatus(str, Enum):
    UNIQUE = "unique"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    STALE_GENERATION = "stale_generation"


class UnflattenClaimKind(str, Enum):
    RETIRED_DISPATCHER_INFRASTRUCTURE = "retired_dispatcher_infrastructure"
    EQUIVALENT_SEMANTIC_ROUTE = "equivalent_semantic_route"
    EXACT_INFEASIBLE_EFFECT = "exact_infeasible_effect"
    LOCAL_ALIAS_EFFECT_SCALARIZATION = "local_alias_effect_scalarization"
    TERMINAL_CYCLE_BREAK = "terminal_cycle_break"
    DETACHED_DEAD_HANDLER_COMPONENT = "detached_dead_handler_component"


class EntryEndpointLivenessReason(str, Enum):
    NO_PROVIDER_EXIT_PATH_LIVE_SAFE_ENDPOINT = "no_provider_exit_path_live_safe_endpoint"


class ProviderConsensusMode(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    SINGLE_PROVIDER = "single_provider"
    MULTI_PROVIDER_CONSENSUS = "multi_provider_consensus"


class StructuralDisposition(str, Enum):
    PRESERVED = "preserved"
    SPLIT = "split"
    FOLDED = "folded"
    AUTHORIZED_RETIREMENT = "authorized_retirement"
    UNACCOUNTED_LOSS = "unaccounted_loss"


class CorridorPathDisposition(str, Enum):
    """Producer-owned disposition for one exact dispatcher corridor path."""

    STRUCTURALLY_COVERED = "structurally_covered"
    SEMANTICALLY_EXCLUDED = "semantically_excluded"
    EXACT_UNREACHABLE_DEFAULT = "exact_unreachable_default"
    RESIDUAL = "residual"


class EffectSiteKind(str, Enum):
    CALL = "call"
    STORE = "store"
    TRAP = "trap"
    RETURN = "return"


class TerminalKind(str, Enum):
    RETURN = "return"
    TRAP = "trap"
    NORETURN_CALL = "noreturn_call"
    STOP = "stop"


class ProjectedSiteLineageKind(str, Enum):
    """The only owner lineages permitted by the projected site closure."""

    SAME_OWNER = "same_owner"
    RELATION_CLONE = "relation_clone"


class TopologyIncidenceKind(str, Enum):
    PREDECESSOR = "predecessor"
    SUCCESSOR = "successor"


class GenericCfgGateKind(str, Enum):
    ENTRY_REACHABILITY = "entry_reachability"
    EFFECTFUL_REACHABILITY = "effectful_reachability"
    TERMINAL_REACHABILITY = "terminal_reachability"


class AuthorityEvidenceKind(str, Enum):
    PHASE_BINDING = "phase_binding"
    TOPOLOGY = "topology"
    STRUCTURAL_LINEAGE = "structural_lineage"
    SEMANTIC_ROUTE = "semantic_route"
    EFFECT_SITE = "effect_site"
    REACHABILITY = "reachability"
    USE_DEF_AUDIT = "use_def_audit"
    CORRIDOR_COVERAGE = "corridor_coverage"
    TERMINAL_CYCLE = "terminal_cycle"
    PATCH_STEP = "patch_step"
    GENERIC_CFG_GATE = "generic_cfg_gate"
    DETACHED_COMPONENT = "detached_component"


class UnflattenJustificationRule(str, Enum):
    UNIQUE_PHASE_BINDING = "unique_phase_binding"
    NONUNIQUE_PHASE_BINDING = "nonunique_phase_binding"
    TOPOLOGY_PRESERVED = "topology_preserved"
    TOPOLOGY_DRIFTED = "topology_drifted"
    SOURCE_PRESERVED = "source_preserved"
    SOURCE_SPLIT_WITH_RECIPROCAL_ORIGINS = "source_split_with_reciprocal_origins"
    SOURCE_FOLDED_WITH_RECIPROCAL_ORIGINS = "source_folded_with_reciprocal_origins"
    SOURCE_LOSS_UNACCOUNTED = "source_loss_unaccounted"
    RETIRED_INFRASTRUCTURE_PROVEN = "retired_infrastructure_proven"
    EQUIVALENT_ROUTE_PROVEN = "equivalent_route_proven"
    EXACT_INFEASIBLE_EFFECT_PROVEN = "exact_infeasible_effect_proven"
    LOCAL_ALIAS_SCALARIZATION_PROVEN = "local_alias_scalarization_proven"
    TERMINAL_CYCLE_BREAK_PROVEN = "terminal_cycle_break_proven"
    ROUTE_MISSING_OR_DRIFTED = "route_missing_or_drifted"
    EFFECT_PRESERVED = "effect_preserved"
    EFFECT_LOST_UNACCOUNTED = "effect_lost_unaccounted"
    SUBJECT_REACHABLE = "subject_reachable"
    SUBJECT_UNREACHABLE = "subject_unreachable"
    USE_DEF_AUDIT_CLEAN = "use_def_audit_clean"
    USE_DEF_AUDIT_UNAVAILABLE = "use_def_audit_unavailable"
    NON_STATE_USE_DEF_SEVERED = "non_state_use_def_severed"
    CORRIDOR_FULLY_COVERED = "corridor_fully_covered"
    CORRIDOR_RESIDUAL_UNACCOUNTED = "corridor_residual_unaccounted"
    HELPER_OWNER_LINEAGE_PROVEN = "helper_owner_lineage_proven"
    RESEGMENTATION_LINEAGE_PROVEN = "resegmentation_lineage_proven"
    GENERIC_CFG_GATE_PASSED = "generic_cfg_gate_passed"
    GENERIC_CFG_GATE_FAILED = "generic_cfg_gate_failed"
    DETACHED_COMPONENT_PROVEN = "detached_component_proven"


class UnflattenAuthorityReason(str, Enum):
    ACCEPTED = "accepted"
    NOT_APPLICABLE = "not_applicable"
    DUAL_AUTHORITY_CHANNEL = "dual_authority_channel"
    LEGACY_ROUTE_EVIDENCE_MISSING = "legacy_route_evidence_missing"
    MALFORMED_PROPOSAL = "malformed_proposal"
    SOURCE_BINDING_FAILED = "source_binding_failed"
    PROJECTED_BINDING_FAILED = "projected_binding_failed"
    LIVE_BINDING_FAILED = "live_binding_failed"
    GRAPH_GENERATION_MISMATCH = "graph_generation_mismatch"
    OBLIGATION_UNPROVEN = "obligation_unproven"
    OBLIGATION_VIOLATED = "obligation_violated"
    OBLIGATION_INCONSISTENT = "obligation_inconsistent"
    OBSERVED_DELTA_UNAUTHORIZED = "observed_delta_unauthorized"
    GENERIC_CFG_GATE_FAILED = "generic_cfg_gate_failed"


class ProposalValidationStage(str, Enum):
    """Closed proposal-invariant boundary for typed rejection diagnostics."""

    ROUNDTRIP = "roundtrip"
    PROPOSAL_POST_INIT = "proposal_post_init"
    USE_DEF = "use_def"
    RETIREMENT_CATALOG = "retirement_catalog"
    EXACT_EFFECT_CORRELATION = "exact_effect_correlation"


class UnflattenPlanRoute(str, Enum):
    ORDINARY = "ordinary"
    TYPED_PROPOSAL = "typed_proposal"
    LEGACY_ADAPTED = "legacy_adapted"


class UnflattenPlanShape(str, Enum):
    EXACT_EFFECT_ONLY = "exact_effect_only"
    PARTIAL_REWRITE = "partial_rewrite"
    FULL_DISPATCHER_RETIREMENT = "full_dispatcher_retirement"


class RetirementPhaseClassification(str, Enum):
    """Transaction-owned classification for one exact plan member."""

    RETIRED = "retired"
    RETAINED = "retained"
    UNACCOUNTED = "unaccounted"
    DRIFTED = "drifted"


@dataclass(frozen=True, slots=True)
class BlockSubjectLocator:
    block_ref: CfgBlockRef
    anchor_ea: int

    def __post_init__(self) -> None:
        _cfg_ref(self.block_ref)
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))


@dataclass(frozen=True, slots=True)
class LogicalFunctionExitSubjectLocator:
    """Exact anchorless logical FUNCTION_EXIT member of one semantic route."""

    block_ref: LogicalBlockRef
    serial: int

    def __post_init__(self) -> None:
        if type(self.block_ref) is not LogicalBlockRef:
            raise TypeError("logical function exit requires a LogicalBlockRef")
        object.__setattr__(self, "serial", _nonnegative(self.serial, "serial"))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ObservedLogicalEndpointOccurrence:
    """One transaction-validated observed occurrence of a projected exit."""

    logical_ref: LogicalBlockRef
    projected_serial: int
    observed_serial: int
    owner_ref: CfgBlockRef
    predecessor_refs: tuple[CfgBlockRef, ...]

    def __post_init__(self) -> None:
        if type(self.logical_ref) is not LogicalBlockRef:
            raise TypeError("logical_ref must be a LogicalBlockRef")
        _nonnegative(self.projected_serial, "projected_serial")
        _nonnegative(self.observed_serial, "observed_serial")
        if self.projected_serial == self.observed_serial:
            raise ValueError("observed logical occurrence requires serial movement")
        _cfg_ref(self.owner_ref, "owner_ref")
        refs = _canonical_cfg_ref_tuple(
            self.predecessor_refs,
            "predecessor_refs",
        )
        if not refs or self.owner_ref not in refs:
            raise ValueError(
                "observed logical occurrence requires its exact plan owner",
            )
        object.__setattr__(self, "predecessor_refs", refs)

    @property
    def occurrence_id(self) -> str:
        return authority_id((
            "unflatten.observed-logical-endpoint-occurrence.v1",
            self.logical_ref,
            self.projected_serial,
            self.observed_serial,
            self.owner_ref,
            self.predecessor_refs,
        ))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ObservedRouteTopologyOccurrence:
    """One binder-minted observed realization of a sealed route relation.

    The transaction validates the live backend shape once and retains the
    projected subject-level pairs that it is allowed to normalize.  Evaluators
    consume this closed receipt; they do not replay FlowGraph topology.
    """

    relation_id: str
    row_id: str
    patch_fact: PatchStepEvidencePayload
    normalized_pairs: tuple[TopologyEdgeRelation, ...]

    def __post_init__(self) -> None:
        _id(self.relation_id, "relation_id")
        _id(self.row_id, "row_id")
        if type(self.patch_fact) is not PatchStepEvidencePayload:
            raise TypeError("patch_fact must be PatchStepEvidencePayload")
        self.patch_fact.__post_init__()
        pairs = _tuple(self.normalized_pairs, "normalized_pairs", sort=True)
        if not pairs or any(type(item) is not TopologyEdgeRelation for item in pairs):
            raise ValueError("normalized_pairs must contain exact topology relations")
        for pair in pairs:
            pair.__post_init__()
        object.__setattr__(self, "normalized_pairs", pairs)

    @property
    def occurrence_id(self) -> str:
        return authority_id((
            "unflatten.observed-route-topology-occurrence.v1",
            self.relation_id,
            self.row_id,
            self.patch_fact,
            self.normalized_pairs,
        ))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ObservedLoweredConditionalTopologyOccurrence:
    """Transaction-owned observation of one exact lowered conditional.

    Some planner-owned conditional lowerings are auxiliary control-flow
    operations rather than rows in ``ProjectedRouteRealization``.  The
    transaction validates their exact projected and observed shapes once and
    carries only this immutable occurrence into semantic evaluation.
    """

    patch_fact: PatchStepEvidencePayload
    source_ref: CfgBlockRef
    false_target_ref: CfgBlockRef
    true_target_ref: CfgBlockRef
    normalized_pairs: tuple[TopologyEdgeRelation, ...]

    def __post_init__(self) -> None:
        if type(self.patch_fact) is not PatchStepEvidencePayload:
            raise TypeError("patch_fact must be PatchStepEvidencePayload")
        self.patch_fact.__post_init__()
        for name in ("source_ref", "false_target_ref", "true_target_ref"):
            _cfg_ref(getattr(self, name), name)
        if len({self.source_ref, self.false_target_ref, self.true_target_ref}) != 3:
            raise ValueError("lowered conditional roles must be distinct")
        pairs = _tuple(self.normalized_pairs, "normalized_pairs", sort=True)
        if not pairs or any(type(item) is not TopologyEdgeRelation for item in pairs):
            raise ValueError("normalized_pairs must contain exact topology relations")
        for pair in pairs:
            pair.__post_init__()
        object.__setattr__(self, "normalized_pairs", pairs)

    @property
    def occurrence_id(self) -> str:
        return authority_id((
            "unflatten.observed-lowered-conditional-topology-occurrence.v1",
            self.patch_fact,
            self.source_ref,
            self.false_target_ref,
            self.true_target_ref,
            self.normalized_pairs,
        ))


@dataclass(frozen=True, slots=True)
class EdgeSubjectLocator:
    source_ref: CfgBlockRef
    source_anchor_ea: int
    target_ref: CfgBlockRef
    target_anchor_ea: int
    edge_role: SemanticEdgeRole

    def __post_init__(self) -> None:
        _cfg_ref(self.source_ref, "source_ref")
        _cfg_ref(self.target_ref, "target_ref")
        object.__setattr__(self, "source_anchor_ea", _ea(self.source_anchor_ea, "source_anchor_ea"))
        object.__setattr__(self, "target_anchor_ea", _ea(self.target_anchor_ea, "target_anchor_ea"))
        _enum(self.edge_role, SemanticEdgeRole, "edge_role")


@dataclass(frozen=True, slots=True)
class RouteSubjectLocator:
    proof_id: str
    atomic_group_id: str
    source_ref: CfgBlockRef
    source_anchor_ea: int
    destination_locators: tuple[BlockSubjectLocator, ...]
    dag_endpoint_locators: tuple[LogicalFunctionExitSubjectLocator, ...] = ()

    def __post_init__(self) -> None:
        _id(self.proof_id, "proof_id")
        _id(self.atomic_group_id, "atomic_group_id")
        _cfg_ref(self.source_ref, "source_ref")
        object.__setattr__(self, "source_anchor_ea", _ea(self.source_anchor_ea, "source_anchor_ea"))
        destinations = _tuple(
            self.destination_locators, "destination_locators", sort=True,
        )
        if not destinations:
            raise ValueError("destination_locators must not be empty")
        if any(type(item) is not BlockSubjectLocator for item in destinations):
            raise TypeError("route destinations must use native block locators")
        if len(set(destinations)) != len(destinations):
            raise ValueError("destination_locators must not contain duplicates")
        dag_endpoints = _tuple(
            self.dag_endpoint_locators, "dag_endpoint_locators", sort=True,
        )
        if any(type(item) is not LogicalFunctionExitSubjectLocator for item in dag_endpoints):
            raise TypeError("route DAG endpoints must use logical function-exit locators")
        if len(set(dag_endpoints)) != len(dag_endpoints):
            raise ValueError("dag_endpoint_locators must not contain duplicates")
        object.__setattr__(self, "destination_locators", destinations)
        object.__setattr__(self, "dag_endpoint_locators", dag_endpoints)

    def native_destination_members(self) -> tuple[BlockSubjectLocator, ...]:
        """Return only physical semantic redirect destinations."""
        return self.destination_locators

    def dag_endpoint_members(self) -> tuple[LogicalFunctionExitSubjectLocator, ...]:
        """Return only anchorless logical decision-DAG closure endpoints."""
        return self.dag_endpoint_locators


@dataclass(frozen=True, slots=True)
class EffectSubjectLocator:
    owner_ref: CfgBlockRef
    owner_anchor_ea: int
    instruction_ea: int
    effect_kind: EffectSiteKind

    def __post_init__(self) -> None:
        _cfg_ref(self.owner_ref, "owner_ref")
        object.__setattr__(self, "owner_anchor_ea", _ea(self.owner_anchor_ea, "owner_anchor_ea"))
        object.__setattr__(self, "instruction_ea", _ea(self.instruction_ea, "instruction_ea"))
        _enum(self.effect_kind, EffectSiteKind, "effect_kind")


@dataclass(frozen=True, slots=True)
class HandlerSubjectLocator:
    block_ref: NativeBlockRef
    anchor_ea: int
    normalized_states: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.block_ref) is not NativeBlockRef:
            raise TypeError("authoritative handler requires a NativeBlockRef")
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))
        states = _tuple(self.normalized_states, "normalized_states", sort=True)
        for state in states:
            _nonnegative(state, "normalized state")
        object.__setattr__(self, "normalized_states", states)


@dataclass(frozen=True, slots=True)
class TerminalSubjectLocator:
    block_ref: CfgBlockRef
    anchor_ea: int
    terminal_kind: TerminalKind
    instruction_ea: int

    def __post_init__(self) -> None:
        _cfg_ref(self.block_ref)
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))
        object.__setattr__(self, "instruction_ea", _ea(self.instruction_ea, "instruction_ea"))
        _enum(self.terminal_kind, TerminalKind, "terminal_kind")


@dataclass(frozen=True, slots=True)
class ValueFlowSubjectLocator:
    fragment_id: str
    state_identity: StorageIdentity
    redirect_owner_refs: tuple[CfgBlockRef, ...]

    def __post_init__(self) -> None:
        _id(self.fragment_id, "fragment_id")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be a StorageIdentity")
        refs = _canonical_cfg_ref_tuple(
            self.redirect_owner_refs, "redirect_owner_refs",
        )
        object.__setattr__(self, "redirect_owner_refs", refs)


@dataclass(frozen=True, slots=True)
class CorridorSubjectLocator:
    corridor_id: str
    entry_ref: CfgBlockRef
    entry_anchor_ea: int
    member_refs: tuple[CfgBlockRef, ...]
    member_anchor_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        _id(self.corridor_id, "corridor_id")
        _cfg_ref(self.entry_ref, "entry_ref")
        object.__setattr__(self, "entry_anchor_ea", _ea(self.entry_anchor_ea, "entry_anchor_ea"))
        raw_pairs = _paired_tuples(
            self.member_refs, self.member_anchor_eas,
            "member_refs", "member_anchor_eas",
        )
        # Corridor members share the same canonical authority-ref ordering as
        # the case-owned retirement catalog.  Keep the ref/anchor association
        # intact while using the canonical byte order for exact replay.
        pairs = tuple(sorted(raw_pairs, key=lambda pair: canonical_bytes(pair[0])))
        for ref, ea in pairs:
            _cfg_ref(ref, "member_refs item")
            _ea(ea, "member_anchor_eas item")
        refs = tuple(pair[0] for pair in pairs)
        eas = tuple(pair[1] for pair in pairs)
        if self.entry_ref not in refs:
            raise ValueError("corridor members must include entry_ref")
        object.__setattr__(self, "member_refs", refs)
        object.__setattr__(self, "member_anchor_eas", eas)


@dataclass(frozen=True, slots=True)
class CorridorCoveragePathNode:
    """One serial-free node in a producer-enumerated corridor path."""

    block_ref: NativeBlockRef | LogicalBlockRef
    anchor_ea: int

    def __post_init__(self) -> None:
        _authority_ref(self.block_ref)
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))


@dataclass(frozen=True, slots=True)
class CorridorSemanticExclusion:
    """Serial-free typed linkage for one producer semantic exclusion."""

    exclusion_id: str
    digest: str
    normalized_state: int
    state_identity: StorageIdentity
    source: CorridorCoveragePathNode
    feeder: CorridorCoveragePathNode | None
    prefix: CorridorCoveragePathNode
    root: CorridorCoveragePathNode

    def __post_init__(self) -> None:
        _id(self.exclusion_id, "exclusion_id")
        _id(self.digest, "digest")
        _nonnegative(self.normalized_state, "normalized_state")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be a StorageIdentity")
        for name in ("source", "prefix", "root"):
            if type(getattr(self, name)) is not CorridorCoveragePathNode:
                raise TypeError(f"{name} must be a CorridorCoveragePathNode")
        if self.feeder is not None and type(self.feeder) is not CorridorCoveragePathNode:
            raise TypeError("feeder must be a CorridorCoveragePathNode or None")
        typed = (
            "unflatten.corridor-semantic-exclusion.v1", self.normalized_state,
            self.state_identity, self.source, self.feeder, self.prefix, self.root,
        )
        if self.exclusion_id != authority_id(typed):
            raise ValueError("exclusion_id does not match serial-free content")
        if self.digest != authority_id(("unflatten.corridor-semantic-exclusion-digest.v1", typed)):
            raise ValueError("exclusion digest does not match serial-free content")


@dataclass(frozen=True, slots=True)
class DefaultGapInitialStateSeed:
    """One route-proven source state entering the dispatcher default gap."""

    normalized_state: int
    route_proof_id: str

    def __post_init__(self) -> None:
        _nonnegative(self.normalized_state, "normalized_state")
        _id(self.route_proof_id, "route_proof_id")


@dataclass(frozen=True, slots=True)
class DefaultGapInfeasibilityExclusion:
    """Producer proof that an exact default arm cannot reach one residual node."""

    exclusion_id: str
    digest: str
    state_width_bytes: int
    state_identity: StorageIdentity
    dispatcher: CorridorCoveragePathNode
    default_entry: CorridorCoveragePathNode
    residual: CorridorCoveragePathNode
    initial_state_seeds: tuple[DefaultGapInitialStateSeed, ...]
    route_proof_ids: tuple[str, ...]
    normalized_reachable_states: tuple[int, ...]

    def __post_init__(self) -> None:
        _id(self.exclusion_id, "exclusion_id")
        _id(self.digest, "digest")
        if type(self.state_width_bytes) is not int or self.state_width_bytes != 4:
            raise ValueError("state_width_bytes must be exact u32 width (4)")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be a StorageIdentity")
        for name in ("dispatcher", "default_entry", "residual"):
            if type(getattr(self, name)) is not CorridorCoveragePathNode:
                raise TypeError(f"{name} must be a CorridorCoveragePathNode")
        seeds = tuple(self.initial_state_seeds)
        if not seeds or any(type(item) is not DefaultGapInitialStateSeed for item in seeds):
            raise TypeError("initial_state_seeds must be a non-empty tuple of closed rows")
        if seeds != tuple(sorted(seeds, key=canonical_bytes)) or len(set(seeds)) != len(seeds):
            raise ValueError("initial_state_seeds must be canonically ordered and unique")
        proofs = _strict_id_tuple(self.route_proof_ids, "route_proof_ids")
        if len(seeds) != len(proofs) or len({seed.route_proof_id for seed in seeds}) != len(seeds) or {seed.route_proof_id for seed in seeds} != set(proofs):
            raise ValueError("initial state seeds must link bijectively to route proofs")
        reachable = tuple(self.normalized_reachable_states)
        if not reachable or any(type(value) is not int or value < 0 or value >= (1 << 32) for value in reachable):
            raise ValueError("normalized_reachable_states must be non-empty u32 states")
        if reachable != tuple(sorted(set(reachable))):
            raise ValueError("normalized_reachable_states must be canonically ordered and unique")
        if any(seed.normalized_state not in reachable for seed in seeds):
            raise ValueError("initial state seeds must be normalized reachable states")
        content = (
            "unflatten.default-gap-infeasibility-exclusion.v2", self.state_width_bytes,
            self.state_identity, self.dispatcher,
            self.default_entry, self.residual, seeds, proofs, reachable,
        )
        if self.exclusion_id != authority_id(content):
            raise ValueError("exclusion_id does not match exact default-gap content")
        if self.digest != authority_id(("unflatten.default-gap-infeasibility-exclusion-digest.v1", content)):
            raise ValueError("exclusion digest does not match exact default-gap content")
        object.__setattr__(self, "initial_state_seeds", seeds)
        object.__setattr__(self, "route_proof_ids", proofs)
        object.__setattr__(self, "normalized_reachable_states", reachable)


@dataclass(frozen=True, slots=True)
class DefaultGapInfeasibilityPath:
    """Nominal v2 path row for a default arm proven unreachable to its residual."""

    path_id: str
    nodes: tuple[CorridorCoveragePathNode, ...]
    state_merge: CorridorCoveragePathNode | None
    exclusion_id: str

    def __post_init__(self) -> None:
        _id(self.path_id, "path_id")
        if type(self.nodes) is not tuple or len(self.nodes) < 2 or any(type(node) is not CorridorCoveragePathNode for node in self.nodes):
            raise TypeError("default-gap path requires at least two closed nodes")
        if len({(node.block_ref, node.anchor_ea) for node in self.nodes}) != len(self.nodes):
            raise ValueError("default-gap path nodes must be unique")
        if self.state_merge is not None and type(self.state_merge) is not CorridorCoveragePathNode:
            raise TypeError("state_merge must be a CorridorCoveragePathNode or None")
        if self.state_merge is not None and self.state_merge not in self.nodes:
            raise ValueError("state merge must be an exact default-gap path node")
        _id(self.exclusion_id, "exclusion_id")
        expected = authority_id((
            "unflatten.default-gap-infeasibility-path.v1", self.nodes,
            self.state_merge, self.exclusion_id,
        ))
        if self.path_id != expected:
            raise ValueError("path_id does not match exact default-gap path content")

    @property
    def disposition(self) -> CorridorPathDisposition:
        return CorridorPathDisposition.EXACT_UNREACHABLE_DEFAULT


@dataclass(frozen=True, slots=True)
class DefaultGapInfeasibilityForecast:
    """Versioned nonempty extension of a legacy corridor forecast."""

    extension_id: str
    base_forecast: CorridorCoverageForecast
    paths: tuple[DefaultGapInfeasibilityPath, ...]
    exclusion_digests: tuple[tuple[str, str], ...]
    exclusions: tuple[DefaultGapInfeasibilityExclusion, ...]

    def __post_init__(self) -> None:
        _id(self.extension_id, "extension_id")
        if type(self.base_forecast) is not CorridorCoverageForecast:
            raise TypeError("base_forecast must be a legacy CorridorCoverageForecast")
        paths = tuple(self.paths)
        if not paths or any(type(path) is not DefaultGapInfeasibilityPath for path in paths):
            raise TypeError("default-gap forecast requires non-empty closed paths")
        if paths != tuple(sorted(paths, key=lambda path: path.path_id)) or len({path.path_id for path in paths}) != len(paths):
            raise ValueError("default-gap paths must be canonically ordered and unique")
        exclusions = tuple(self.exclusions)
        if not exclusions or any(type(item) is not DefaultGapInfeasibilityExclusion for item in exclusions):
            raise TypeError("default-gap forecast requires non-empty closed exclusions")
        if exclusions != tuple(sorted(exclusions, key=lambda item: item.exclusion_id)) or len({item.exclusion_id for item in exclusions}) != len(exclusions):
            raise ValueError("default-gap exclusions must be canonically ordered and unique")
        digests = tuple(self.exclusion_digests)
        if type(self.exclusion_digests) is not tuple or digests != tuple(sorted(digests)) or len(set(digests)) != len(digests):
            raise ValueError("default-gap exclusion digests must be canonical and unique")
        expected_digests = tuple((item.exclusion_id, item.digest) for item in exclusions)
        if digests != expected_digests:
            raise ValueError("default-gap digest rows must equal sealed exclusion digests")
        if {path.exclusion_id for path in paths} != {item.exclusion_id for item in exclusions} or len(paths) != len(exclusions):
            raise ValueError("default-gap path linkage must be bijective")
        if {item.exclusion_id for item in exclusions} & {
            exclusion_id for path in self.base_forecast.paths for exclusion_id in path.semantic_exclusion_ids
        }:
            raise ValueError("default-gap exclusions must not overlap route semantic exclusions")
        exclusions_by_id = {item.exclusion_id: item for item in exclusions}
        residual_paths = {
            (path.nodes, path.state_merge): path
            for path in self.base_forecast.paths
            if path.disposition is CorridorPathDisposition.RESIDUAL
        }
        if len(residual_paths) != sum(
            path.disposition is CorridorPathDisposition.RESIDUAL
            for path in self.base_forecast.paths
        ):
            raise ValueError("base residual paths must have unique exact coordinates")
        if any(
            path.nodes[-1].block_ref != self.base_forecast.dispatcher_ref
            or path.nodes[-1].anchor_ea != self.base_forecast.dispatcher_anchor_ea
            or exclusions_by_id[path.exclusion_id].dispatcher != path.nodes[-1]
            or (path.nodes, path.state_merge) not in residual_paths
            for path in paths
        ):
            raise ValueError("default-gap path dispatcher identity drifted or lacks exact base residual linkage")
        if len({residual_paths[(path.nodes, path.state_merge)].path_id for path in paths}) != len(paths):
            raise ValueError("default-gap paths must link bijectively to base residual paths")
        if self.extension_id != authority_id((
            "unflatten.default-gap-infeasibility-forecast.v1", self.base_forecast,
            paths, digests, exclusions,
        )):
            raise ValueError("extension_id does not match exact default-gap forecast content")
        object.__setattr__(self, "paths", paths)
        object.__setattr__(self, "exclusion_digests", digests)
        object.__setattr__(self, "exclusions", exclusions)


@dataclass(frozen=True, slots=True)
class CorridorCoveragePath:
    """A closed path row; no backend serial or live graph object is retained."""

    path_id: str
    nodes: tuple[CorridorCoveragePathNode, ...]
    state_merge: CorridorCoveragePathNode | None
    disposition: CorridorPathDisposition
    semantic_exclusion_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.path_id, "path_id")
        if type(self.nodes) is not tuple or len(self.nodes) < 2:
            raise TypeError("corridor path requires at least two exact nodes")
        if any(type(node) is not CorridorCoveragePathNode for node in self.nodes):
            raise TypeError("corridor path nodes must be closed nominal rows")
        if len({(node.block_ref, node.anchor_ea) for node in self.nodes}) != len(self.nodes):
            raise ValueError("corridor path nodes must be unique")
        if self.state_merge is not None and type(self.state_merge) is not CorridorCoveragePathNode:
            raise TypeError("state_merge must be a CorridorCoveragePathNode or None")
        _enum(self.disposition, CorridorPathDisposition, "disposition")
        if type(self.semantic_exclusion_ids) is not tuple:
            raise TypeError("semantic_exclusion_ids must be an exact tuple")
        exclusions = _tuple(self.semantic_exclusion_ids, "semantic_exclusion_ids")
        if exclusions != tuple(sorted(exclusions)):
            raise ValueError("semantic_exclusion_ids must be canonically ordered")
        for value in exclusions:
            _id(value, "semantic_exclusion_ids item")
        object.__setattr__(self, "semantic_exclusion_ids", exclusions)
        if self.disposition is CorridorPathDisposition.SEMANTICALLY_EXCLUDED and not exclusions:
            raise ValueError("semantic exclusion disposition requires exclusion IDs")
        if self.disposition is not CorridorPathDisposition.SEMANTICALLY_EXCLUDED and exclusions:
            raise ValueError("only semantically excluded paths may carry semantic exclusion IDs")
        if self.disposition is CorridorPathDisposition.EXACT_UNREACHABLE_DEFAULT:
            raise ValueError("exact unreachable default paths require DefaultGapInfeasibilityPath")
        node_pairs = {(node.block_ref, node.anchor_ea) for node in self.nodes}
        if self.state_merge is not None and (
            self.state_merge.block_ref, self.state_merge.anchor_ea
        ) not in node_pairs:
            raise ValueError("state merge must be an exact path node")
        expected_id = authority_id((
            "unflatten.corridor-coverage-path.v1", self.nodes,
            self.state_merge, self.disposition, self.semantic_exclusion_ids,
        ))
        if self.path_id != expected_id:
            raise ValueError("path_id does not match serial-free path content")


@dataclass(frozen=True, slots=True)
class CorridorCoverageForecast:
    """Sealed producer forecast for the exact corridor-path domain."""

    forecast_id: str
    plan_id: str
    function_ea: int
    source_native_key: NativePreanalysisKey
    source_generation: int
    dispatcher_ref: NativeBlockRef | LogicalBlockRef
    dispatcher_anchor_ea: int
    paths: tuple[CorridorCoveragePath, ...]
    covered_path_ids: tuple[str, ...]
    residual_path_ids: tuple[str, ...]
    enumeration_complete: bool
    semantic_exclusion_digests: tuple[tuple[str, str], ...]
    semantic_exclusions: tuple[CorridorSemanticExclusion, ...]
    semantic_exclusion_path_ids: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        _id(self.forecast_id, "forecast_id")
        _id(self.plan_id, "plan_id")
        object.__setattr__(self, "function_ea", _ea(self.function_ea, "function_ea"))
        if type(self.source_native_key) is not NativePreanalysisKey:
            raise TypeError("source_native_key must be a NativePreanalysisKey")
        _generation(self.source_generation, "source_generation")
        _authority_ref(self.dispatcher_ref, "dispatcher_ref")
        object.__setattr__(self, "dispatcher_anchor_ea", _ea(self.dispatcher_anchor_ea, "dispatcher_anchor_ea"))
        if type(self.paths) is not tuple:
            raise TypeError("corridor forecast paths must be an exact tuple")
        if any(type(path) is not CorridorCoveragePath for path in self.paths):
            raise TypeError("corridor forecast paths must be closed nominal rows")
        paths = tuple(sorted(self.paths, key=lambda path: path.path_id))
        if paths != self.paths or len({path.path_id for path in paths}) != len(paths):
            raise ValueError("corridor forecast paths must be canonically ordered and unique")
        path_ids = tuple(path.path_id for path in paths)
        covered = _strict_id_tuple(self.covered_path_ids, "covered_path_ids")
        residual = _strict_id_tuple(self.residual_path_ids, "residual_path_ids")
        if set(covered) & set(residual) or set(covered) | set(residual) != set(path_ids):
            raise ValueError("corridor path partition must be disjoint and exhaustive")
        disposition_by_id = {path.path_id: path.disposition for path in paths}
        if any(disposition_by_id[path_id] is CorridorPathDisposition.RESIDUAL for path_id in covered):
            raise ValueError("residual disposition cannot be in covered partition")
        if any(disposition_by_id[path_id] is not CorridorPathDisposition.RESIDUAL for path_id in residual):
            raise ValueError("covered disposition cannot be in residual partition")
        if type(self.enumeration_complete) is not bool:
            raise TypeError("enumeration_complete must be an exact bool")
        digests = tuple(self.semantic_exclusion_digests)
        if type(self.semantic_exclusion_digests) is not tuple or any(
            type(row) is not tuple or len(row) != 2 or type(row[0]) is not str or type(row[1]) is not str
            for row in digests
        ):
            raise TypeError("semantic exclusion digests must be exact (ID, digest) rows")
        if digests != tuple(sorted(set(digests))) or any(
            not _validate_id(row[0], "semantic exclusion ID") or not _validate_id(row[1], "semantic exclusion digest")
            for row in digests
        ):
            raise ValueError("semantic exclusion digests must be canonical and unique")
        exclusion_ids = {value for path in paths for value in path.semantic_exclusion_ids}
        if exclusion_ids != {row[0] for row in digests}:
            raise ValueError("semantic exclusion linkage is not exact")
        exclusions = tuple(self.semantic_exclusions)
        if type(exclusions) is not tuple or any(type(item) is not CorridorSemanticExclusion for item in exclusions):
            raise TypeError("semantic exclusions must be exact closed rows")
        if tuple(item.exclusion_id for item in exclusions) != tuple(sorted(item.exclusion_id for item in exclusions)):
            raise ValueError("semantic exclusions must be canonically ordered")
        if {item.exclusion_id for item in exclusions} != exclusion_ids:
            raise ValueError("semantic exclusion records do not match path linkage")
        exclusion_paths = tuple(self.semantic_exclusion_path_ids)
        if type(exclusion_paths) is not tuple or any(
            type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
            or type(row[1]) is not tuple
            for row in exclusion_paths
        ) or exclusion_paths != tuple(sorted(exclusion_paths)):
            raise ValueError("semantic exclusion path linkage is not canonical")
        if {row[0] for row in exclusion_paths} != exclusion_ids:
            raise ValueError("semantic exclusion path linkage is incomplete")
        path_universe = set(path_ids)
        for exclusion_id, linked_paths in exclusion_paths:
            if not linked_paths or linked_paths != tuple(sorted(set(linked_paths))) or not set(linked_paths) <= path_universe:
                raise ValueError("semantic exclusion path linkage is malformed")
            expected_linked = tuple(path.path_id for path in paths if exclusion_id in path.semantic_exclusion_ids)
            if linked_paths != expected_linked:
                raise ValueError("semantic exclusion path linkage disagrees with paths")
        if any(
            path.nodes[-1].block_ref != self.dispatcher_ref
            or path.nodes[-1].anchor_ea != self.dispatcher_anchor_ea
            for path in paths
        ):
            raise ValueError("forecast path dispatcher identity drifted")
        if self.forecast_id != authority_id((
            "unflatten.corridor-coverage-forecast.v1", self.plan_id, self.function_ea,
            self.source_native_key, self.source_generation, self.dispatcher_ref,
            self.dispatcher_anchor_ea, self.paths, covered, residual,
            self.enumeration_complete, digests, exclusions, exclusion_paths,
        )):
            raise ValueError("forecast_id does not match canonical forecast content")


@dataclass(frozen=True, slots=True)
class CorridorSemanticExclusionCorrelation:
    """One binder-owned route linkage for a candidate-prefix exclusion."""

    exclusion_id: str
    exclusion_digest: str
    path_id: str
    claim_id: str
    proof_id: str
    ordered_prefix: tuple[CorridorCoveragePathNode, ...]
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    phase_result_id: str

    def __post_init__(self) -> None:
        for name in ("exclusion_id", "exclusion_digest", "path_id", "claim_id", "proof_id", "phase_result_id"):
            _id(getattr(self, name), name)
        if type(self.ordered_prefix) is not tuple or not self.ordered_prefix:
            raise TypeError("ordered_prefix must be a non-empty tuple")
        if any(type(node) is not CorridorCoveragePathNode for node in self.ordered_prefix):
            raise TypeError("ordered_prefix must contain closed path nodes")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")

    @property
    def content_key(self) -> tuple[object, ...]:
        return (
            self.exclusion_id, self.exclusion_digest, self.path_id, self.claim_id, self.proof_id,
            self.ordered_prefix, self.source_fingerprint,
            self.candidate_fingerprint, self.source_generation,
            self.candidate_generation,
        )


@dataclass(frozen=True, slots=True)
class DefaultGapInfeasibilityCorrelation:
    """Binder-owned phase linkage for one exact default-gap exclusion/path."""

    exclusion_id: str
    exclusion_digest: str
    path_id: str
    dispatcher: CorridorCoveragePathNode
    default_entry: CorridorCoveragePathNode
    residual: CorridorCoveragePathNode
    initial_state_seeds: tuple[DefaultGapInitialStateSeed, ...]
    route_proof_ids: tuple[str, ...]
    normalized_reachable_states: tuple[int, ...]
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    phase_result_id: str

    def __post_init__(self) -> None:
        for name in ("exclusion_id", "exclusion_digest", "path_id", "source_fingerprint", "candidate_fingerprint", "phase_result_id"):
            _id(getattr(self, name), name)
        for name in ("dispatcher", "default_entry", "residual"):
            if type(getattr(self, name)) is not CorridorCoveragePathNode:
                raise TypeError(f"{name} must be a CorridorCoveragePathNode")
        seeds = tuple(self.initial_state_seeds)
        if not seeds or any(type(item) is not DefaultGapInitialStateSeed for item in seeds):
            raise TypeError("initial_state_seeds must be non-empty closed rows")
        if seeds != tuple(sorted(seeds, key=canonical_bytes)) or len({seed.route_proof_id for seed in seeds}) != len(seeds):
            raise ValueError("initial_state_seeds must be canonical with unique proof IDs")
        proofs = _strict_id_tuple(self.route_proof_ids, "route_proof_ids")
        if len(seeds) != len(proofs) or {seed.route_proof_id for seed in seeds} != set(proofs):
            raise ValueError("initial state seeds must link bijectively to route proofs")
        states = tuple(self.normalized_reachable_states)
        if not states or states != tuple(sorted(set(states))) or any(type(value) is not int or value < 0 or value >= (1 << 32) for value in states):
            raise ValueError("normalized_reachable_states must be canonical u32 states")
        if any(seed.normalized_state not in states for seed in seeds):
            raise ValueError("initial state seeds must be normalized reachable states")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")

    @property
    def content_key(self) -> tuple[object, ...]:
        return (
            self.exclusion_id, self.exclusion_digest, self.path_id,
            self.dispatcher, self.default_entry, self.residual,
            self.initial_state_seeds, self.route_proof_ids,
            self.normalized_reachable_states,
            self.source_fingerprint, self.candidate_fingerprint,
            self.source_generation, self.candidate_generation,
        )


@dataclass(frozen=True, slots=True)
class CorridorCoveragePhaseResult:
    """Transaction/binder result consumed by the evaluator as one aggregate fact."""

    result_id: str
    forecast_id: str
    phase: UnflattenAuthorityPhase
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    covered_path_ids: tuple[str, ...]
    residual_path_ids: tuple[str, ...]
    drifted_path_ids: tuple[str, ...]
    enumeration_complete: bool
    matched_semantic_exclusion_ids: tuple[str, ...]
    source_dispatcher_reachable: bool = False
    candidate_dispatcher_reachable: bool = False
    semantic_exclusion_correlations: tuple[CorridorSemanticExclusionCorrelation, ...] = ()
    comparison_region_subject_ids: tuple[str, ...] = ()
    dispatcher_subject_id: str | None = None

    def __post_init__(self) -> None:
        _id(self.result_id, "result_id")
        _id(self.forecast_id, "forecast_id")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        for name in ("covered_path_ids", "residual_path_ids", "drifted_path_ids", "matched_semantic_exclusion_ids"):
            values = _strict_id_tuple(getattr(self, name), name)
            object.__setattr__(self, name, values)
        if set(self.covered_path_ids) & set(self.residual_path_ids) or set(self.drifted_path_ids) & (set(self.covered_path_ids) | set(self.residual_path_ids)):
            raise ValueError("phase path partitions overlap")
        if type(self.enumeration_complete) is not bool:
            raise TypeError("enumeration_complete must be an exact bool")
        if type(self.source_dispatcher_reachable) is not bool or type(self.candidate_dispatcher_reachable) is not bool:
            raise TypeError("dispatcher reachability flags must be exact bools")
        correlations = tuple(self.semantic_exclusion_correlations)
        if any(type(item) is not CorridorSemanticExclusionCorrelation for item in correlations):
            raise TypeError("semantic exclusion correlations must be closed rows")
        if correlations != tuple(sorted(correlations, key=lambda item: (item.exclusion_id, item.path_id))):
            raise ValueError("semantic exclusion correlations must be canonically ordered")
        if len({(item.exclusion_id, item.path_id) for item in correlations}) != len(correlations):
            raise ValueError("semantic exclusion correlations must be unique by exclusion/path")
        if {item.exclusion_id for item in correlations} != set(self.matched_semantic_exclusion_ids):
            raise ValueError("semantic exclusion correlations must match matched IDs")
        if any(
            item.phase_result_id != self.result_id
            or item.source_fingerprint != self.source_fingerprint
            or item.candidate_fingerprint != self.candidate_fingerprint
            or item.source_generation != self.source_generation
            or item.candidate_generation != self.candidate_generation
            or item.path_id not in self.covered_path_ids
            for item in correlations
        ):
            raise ValueError("semantic exclusion correlation coordinates are stale")
        object.__setattr__(self, "semantic_exclusion_correlations", correlations)
        comparison_region = _strict_id_tuple(
            self.comparison_region_subject_ids,
            "comparison_region_subject_ids",
        )
        object.__setattr__(self, "comparison_region_subject_ids", comparison_region)
        if self.dispatcher_subject_id is not None:
            _id(self.dispatcher_subject_id, "dispatcher_subject_id")
            if self.dispatcher_subject_id not in comparison_region:
                raise ValueError("dispatcher subject must belong to comparison region")
        canonical_content = (
            "unflatten.corridor-coverage-phase.v1", self.forecast_id,
            self.phase, self.source_fingerprint, self.candidate_fingerprint,
            self.source_generation, self.candidate_generation,
            self.covered_path_ids, self.residual_path_ids, self.drifted_path_ids,
            self.enumeration_complete, self.matched_semantic_exclusion_ids,
            self.source_dispatcher_reachable, self.candidate_dispatcher_reachable,
            tuple(item.content_key for item in correlations),
        )
        if self.comparison_region_subject_ids:
            canonical_content = (*canonical_content, self.comparison_region_subject_ids)
        if self.dispatcher_subject_id is not None:
            canonical_content = (*canonical_content, self.dispatcher_subject_id)
        if self.result_id != authority_id(canonical_content):
            raise ValueError("result_id does not match canonical phase result content")

    @property
    def full(self) -> bool:
        return (
            self.enumeration_complete
            and self.source_dispatcher_reachable
            and not self.candidate_dispatcher_reachable
            and not self.residual_path_ids
            and not self.drifted_path_ids
        )


@dataclass(frozen=True, slots=True, weakref_slot=True)
class DefaultGapInfeasibilityPhaseResult:
    """Versioned binder result that reuses one exact default-gap forecast."""

    result_id: str
    base_result: CorridorCoveragePhaseResult
    forecast: DefaultGapInfeasibilityForecast
    phase: UnflattenAuthorityPhase
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    matched_exclusion_ids: tuple[str, ...]
    correlations: tuple[DefaultGapInfeasibilityCorrelation, ...]

    def __post_init__(self) -> None:
        _id(self.result_id, "result_id")
        if type(self.base_result) is not CorridorCoveragePhaseResult:
            raise TypeError("base_result must be a legacy CorridorCoveragePhaseResult")
        if type(self.forecast) is not DefaultGapInfeasibilityForecast:
            raise TypeError("forecast must be DefaultGapInfeasibilityForecast")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        if (
            self.base_result.forecast_id != self.forecast.base_forecast.forecast_id
            or self.base_result.phase is not self.phase
            or self.base_result.source_fingerprint != self.source_fingerprint
            or self.base_result.candidate_fingerprint != self.candidate_fingerprint
            or self.base_result.source_generation != self.source_generation
            or self.base_result.candidate_generation != self.candidate_generation
        ):
            raise ValueError("default-gap phase coordinates differ from base result")
        matched = _strict_id_tuple(self.matched_exclusion_ids, "matched_exclusion_ids")
        correlations = tuple(self.correlations)
        if correlations != tuple(sorted(correlations, key=lambda item: (item.exclusion_id, item.path_id))) or len(correlations) != len(matched):
            raise ValueError("default-gap correlations must be canonically ordered and bijective")
        if any(type(item) is not DefaultGapInfeasibilityCorrelation for item in correlations):
            raise TypeError("default-gap correlations must be closed rows")
        expected_exclusions = {item.exclusion_id: item for item in self.forecast.exclusions}
        expected_paths = {item.path_id: item for item in self.forecast.paths}
        if {item.exclusion_id for item in correlations} != set(matched) or len({item.path_id for item in correlations}) != len(correlations):
            raise ValueError("default-gap correlations must exactly cover matched exclusions")
        for item in correlations:
            exclusion = expected_exclusions.get(item.exclusion_id)
            path = expected_paths.get(item.path_id)
            if exclusion is None or path is None or path.exclusion_id != exclusion.exclusion_id:
                raise ValueError("default-gap correlation references foreign forecast authority")
            if (
                item.exclusion_digest != exclusion.digest
                or item.dispatcher != exclusion.dispatcher
                or item.default_entry != exclusion.default_entry
                or item.residual != exclusion.residual
                or item.initial_state_seeds != exclusion.initial_state_seeds
                or item.route_proof_ids != exclusion.route_proof_ids
                or item.normalized_reachable_states != exclusion.normalized_reachable_states
                or item.phase_result_id != self.result_id
                or item.source_fingerprint != self.source_fingerprint
                or item.candidate_fingerprint != self.candidate_fingerprint
                or item.source_generation != self.source_generation
                or item.candidate_generation != self.candidate_generation
            ):
                raise ValueError("default-gap correlation content or phase coordinates are stale")
        if set(matched) & set(self.base_result.matched_semantic_exclusion_ids):
            raise ValueError("default-gap exclusions must not overlap route semantic exclusions")
        content = (
            "unflatten.default-gap-infeasibility-phase.v1", self.base_result,
            self.forecast, self.phase, self.source_fingerprint,
            self.candidate_fingerprint, self.source_generation,
            self.candidate_generation, matched,
            tuple(item.content_key for item in correlations),
        )
        if self.result_id != authority_id(content):
            raise ValueError("result_id does not match exact default-gap phase content")
        object.__setattr__(self, "matched_exclusion_ids", matched)
        object.__setattr__(self, "correlations", correlations)


CorridorCoverageForecastAuthority: TypeAlias = (
    CorridorCoverageForecast | DefaultGapInfeasibilityForecast
)
CorridorCoveragePhaseResultAuthority: TypeAlias = (
    CorridorCoveragePhaseResult | DefaultGapInfeasibilityPhaseResult
)


def corridor_base_forecast(
    forecast: CorridorCoverageForecastAuthority,
) -> CorridorCoverageForecast:
    """Return the legacy corridor record underlying one closed authority union."""
    if type(forecast) is CorridorCoverageForecast:
        return forecast
    if type(forecast) is DefaultGapInfeasibilityForecast:
        return forecast.base_forecast
    raise TypeError("corridor forecast must be a closed authority record")


def corridor_base_phase_result(
    result: CorridorCoveragePhaseResultAuthority,
) -> CorridorCoveragePhaseResult:
    """Return the legacy phase record underlying one closed authority union."""
    if type(result) is CorridorCoveragePhaseResult:
        return result
    if type(result) is DefaultGapInfeasibilityPhaseResult:
        return result.base_result
    raise TypeError("corridor phase result must be a closed authority record")


def _validate_corridor_authority_pair(
    forecast: CorridorCoverageForecastAuthority,
    result: CorridorCoveragePhaseResultAuthority,
) -> tuple[CorridorCoverageForecast, CorridorCoveragePhaseResult]:
    """Validate the nominal wrapper occurrence before exposing legacy coordinates."""
    if type(forecast) is CorridorCoverageForecast:
        if type(result) is not CorridorCoveragePhaseResult:
            raise TypeError("legacy corridor forecast requires legacy phase result")
        forecast.__post_init__()
        result.__post_init__()
        base_forecast, base_result = forecast, result
    if type(forecast) is DefaultGapInfeasibilityForecast:
        if type(result) is not DefaultGapInfeasibilityPhaseResult:
            raise TypeError("default-gap corridor forecast requires default-gap phase result")
        forecast.__post_init__()
        result.__post_init__()
        if (
            result.forecast.extension_id != forecast.extension_id
            or result.forecast != forecast
        ):
            raise ValueError("default-gap phase result carries a foreign forecast")
        if result.base_result.forecast_id != forecast.base_forecast.forecast_id:
            raise ValueError("default-gap phase result base forecast differs from wrapper")
        expected_exclusions = {item.exclusion_id for item in forecast.exclusions}
        expected_paths = {item.path_id for item in forecast.paths}
        if set(result.matched_exclusion_ids) != expected_exclusions:
            raise ValueError("default-gap phase result does not exactly cover forecast exclusions")
        if {item.exclusion_id for item in result.correlations} != expected_exclusions:
            raise ValueError("default-gap correlation exclusion IDs differ from forecast")
        if {item.path_id for item in result.correlations} != expected_paths:
            raise ValueError("default-gap correlation path IDs differ from forecast")
        path_exclusions = {item.path_id: item.exclusion_id for item in forecast.paths}
        if any(
            path_exclusions.get(item.path_id) != item.exclusion_id
            for item in result.correlations
        ):
            raise ValueError("default-gap correlation path linkage differs from forecast")
        base_forecast, base_result = forecast.base_forecast, result.base_result
    elif type(forecast) is not CorridorCoverageForecast:
        raise TypeError("corridor forecast must be a closed authority record")
    if base_result.forecast_id != base_forecast.forecast_id:
        raise ValueError("corridor phase result is foreign to the forecast")
    partitions = (
        set(base_result.covered_path_ids),
        set(base_result.residual_path_ids),
        set(base_result.drifted_path_ids),
    )
    if any(left & right for index, left in enumerate(partitions) for right in partitions[index + 1:]):
        raise ValueError("corridor phase result path partitions overlap")
    if set().union(*partitions) != {path.path_id for path in base_forecast.paths}:
        raise ValueError("corridor phase result path partitions do not exactly cover forecast")
    return base_forecast, base_result


def _same_corridor_forecast_content(
    left: CorridorCoverageForecastAuthority | None,
    right: CorridorCoverageForecastAuthority | None,
) -> bool:
    """Compare sealed legacy or versioned forecast content across persistence."""
    if left is None or right is None:
        return left is right
    if type(left) is DefaultGapInfeasibilityForecast or type(right) is DefaultGapInfeasibilityForecast:
        return (
            type(left) is DefaultGapInfeasibilityForecast
            and type(right) is DefaultGapInfeasibilityForecast
            and left.extension_id == right.extension_id
            and left == right
        )
    return type(left) is CorridorCoverageForecast and type(right) is CorridorCoverageForecast and left == right


@dataclass(frozen=True, slots=True, weakref_slot=True)
class DetachedDeadHandlerComponentSourceResult:
    """Immutable source-side proof material for a detached handler exception.

    This is minted while preparing the projected transaction and is deliberately
    reused by observed verification; a post-apply graph must never become the
    source of this allowance.
    """

    result_id: str
    claim_id: str
    corridor_forecast_id: str
    corridor_coverage_result_id: str
    source_fingerprint: str
    source_generation: int
    dispatcher_subject_id: str
    dispatcher_block_ref: CfgBlockRef
    dead_handler_subject_ids: tuple[str, ...]
    retained_handler_subject_ids: tuple[str, ...]
    component_subject_ids: tuple[str, ...]
    comparison_region_subject_ids: tuple[str, ...]
    source_reachable_subject_ids: tuple[str, ...]
    dead_handler_block_refs: tuple[CfgBlockRef, ...]
    retained_handler_block_refs: tuple[CfgBlockRef, ...]
    comparison_region_block_refs: tuple[CfgBlockRef, ...]
    terminal_digest: str
    effect_digest: str
    topology_digest: str
    source_reachable_block_refs: tuple[CfgBlockRef, ...]
    component_block_refs: tuple[CfgBlockRef, ...]
    remainder_block_refs: tuple[CfgBlockRef, ...]
    terminal_site_keys: tuple[tuple[object, int, TerminalKind], ...]
    effect_site_keys: tuple[tuple[object, int, EffectSiteKind], ...]
    source_blocks: tuple[InventoryBlockObservation, ...]

    def __post_init__(self) -> None:
        for name in ("result_id", "claim_id", "corridor_forecast_id", "corridor_coverage_result_id", "source_fingerprint", "dispatcher_subject_id", "terminal_digest", "effect_digest", "topology_digest"):
            _id(getattr(self, name), name)
        _generation(self.source_generation, "source_generation")
        _authority_ref(self.dispatcher_block_ref, "dispatcher_block_ref")
        for name in ("dead_handler_subject_ids", "retained_handler_subject_ids", "component_subject_ids", "comparison_region_subject_ids", "source_reachable_subject_ids"):
            values = _strict_id_tuple(getattr(self, name), name)
            if not values:
                raise ValueError(f"{name} must not be empty")
            object.__setattr__(self, name, values)
        for name in (
            "dead_handler_block_refs", "retained_handler_block_refs",
            "comparison_region_block_refs", "source_reachable_block_refs",
            "component_block_refs",
        ):
            values = _tuple(getattr(self, name), name)
            if not values:
                raise ValueError(f"{name} must not be empty")
            if any(type(value) not in _CFG_REF_TYPES for value in values):
                raise TypeError(f"{name} must contain exact CFG block refs")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicate refs")
            object.__setattr__(self, name, values)
        remainder = _tuple(self.remainder_block_refs, "remainder_block_refs")
        if any(type(value) not in _CFG_REF_TYPES for value in remainder):
            raise TypeError("remainder_block_refs must contain exact CFG block refs")
        if len(set(remainder)) != len(remainder):
            raise ValueError("remainder_block_refs must not contain duplicate refs")
        object.__setattr__(self, "remainder_block_refs", remainder)
        if set(self.dead_handler_subject_ids) & set(self.retained_handler_subject_ids):
            raise ValueError("dead and retained handler partitions overlap")
        if set(self.dead_handler_block_refs) & set(self.retained_handler_block_refs):
            raise ValueError("dead and retained handler block partitions overlap")
        if not set(self.dead_handler_block_refs) <= set(self.component_block_refs):
            raise ValueError("detached component must contain every dead handler")
        if self.dispatcher_block_ref not in set(self.comparison_region_block_refs):
            raise ValueError("comparison region must contain the dispatcher")
        reachable_refs = set(self.source_reachable_block_refs)
        if not (
            {self.dispatcher_block_ref}
            | set(self.dead_handler_block_refs)
            | set(self.retained_handler_block_refs)
            | set(self.comparison_region_block_refs)
            | set(self.component_block_refs)
            | set(self.remainder_block_refs)
        ) <= reachable_refs:
            raise ValueError("detached source facts contain a non-reachable block ref")
        blocks = _tuple(self.source_blocks, "source_blocks")
        if any(type(block) is not InventoryBlockObservation for block in blocks):
            raise TypeError("source_blocks must contain exact inventory block rows")
        for block in blocks:
            block.__post_init__()
        if tuple(block.serial for block in blocks) != tuple(sorted(block.serial for block in blocks)):
            raise ValueError("source_blocks must be in canonical serial order")
        if any(block.block_ref is None for block in blocks):
            raise ValueError("detached source block rows require stable refs")
        if {block.block_ref for block in blocks} != reachable_refs:
            raise ValueError("source_blocks must cover the exact reachable source refs")
        object.__setattr__(self, "source_blocks", blocks)
        content = ("unflatten.detached-dead-handler-component-source.v2", self.claim_id,
                   self.corridor_forecast_id, self.corridor_coverage_result_id,
                   self.source_fingerprint, self.source_generation,
                   self.dispatcher_subject_id, self.dispatcher_block_ref,
                   self.dead_handler_subject_ids, self.retained_handler_subject_ids,
                   self.component_subject_ids, self.comparison_region_subject_ids,
                   self.source_reachable_subject_ids,
                   self.dead_handler_block_refs, self.retained_handler_block_refs,
                   self.comparison_region_block_refs, self.terminal_digest,
                   self.effect_digest, self.topology_digest,
                   self.source_reachable_block_refs, self.component_block_refs,
                   self.remainder_block_refs, self.terminal_site_keys,
                   self.effect_site_keys, self.source_blocks)
        if self.result_id != authority_id(content):
            raise ValueError("result_id does not match canonical detached component source content")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class DetachedDeadHandlerComponentPhaseResult:
    """Sealed binder result for one detached-component claim and phase."""

    result_id: str
    claim_id: str
    phase: UnflattenAuthorityPhase
    corridor_coverage_result_id: str
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    accepted: bool
    source_result_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("result_id", "claim_id", "corridor_coverage_result_id", "source_fingerprint", "candidate_fingerprint"):
            _id(getattr(self, name), name)
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be an exact bool")
        if self.source_result_id is not None:
            _id(self.source_result_id, "source_result_id")
        if self.accepted and self.source_result_id is None:
            raise ValueError("accepted detached component result requires a sealed source result")
        if self.result_id != authority_id((
            "unflatten.detached-dead-handler-component-phase.v1", self.claim_id,
            self.phase, self.corridor_coverage_result_id, self.source_fingerprint,
            self.candidate_fingerprint, self.source_generation,
            self.candidate_generation, self.accepted, self.source_result_id,
        )):
            raise ValueError("result_id does not match canonical detached component phase result content")


@dataclass(frozen=True, slots=True)
class DetachedComponentEvidencePayload:
    """Exact evidence wrapper for one sealed detached-component phase result."""

    phase_result_id: str
    claim_id: str
    corridor_coverage_result_id: str
    phase: UnflattenAuthorityPhase
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    accepted: bool
    authorized_subject_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("phase_result_id", "claim_id", "corridor_coverage_result_id", "source_fingerprint", "candidate_fingerprint"):
            _id(getattr(self, name), name)
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be an exact bool")
        subjects = _strict_id_tuple(self.authorized_subject_ids, "authorized_subject_ids")
        if not subjects:
            raise ValueError("authorized_subject_ids must not be empty")
        object.__setattr__(self, "authorized_subject_ids", subjects)


def _terminal_cycle_refs(
    values: object, label: str, *, nonempty: bool = True,
) -> tuple[NativeBlockRef | LogicalBlockRef, ...]:
    if type(values) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    refs = tuple(_authority_ref(value, f"{label} item") for value in values)
    if nonempty and not refs:
        raise ValueError(f"{label} must not be empty")
    if len(set(refs)) != len(refs):
        raise ValueError(f"{label} must be unique")
    if refs != tuple(sorted(refs, key=_structural_key)):
        raise ValueError(f"{label} must be in canonical order")
    return refs


def _terminal_cycle_edges(
    values: object, label: str, residue: tuple[NativeBlockRef | LogicalBlockRef, ...],
) -> tuple[tuple[NativeBlockRef | LogicalBlockRef, NativeBlockRef | LogicalBlockRef], ...]:
    if type(values) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    edges = []
    residue_set = set(residue)
    for index, edge in enumerate(values):
        if type(edge) is not tuple or len(edge) != 2:
            raise TypeError(f"{label}[{index}] must be a ref pair")
        source, target = (
            _authority_ref(edge[0], f"{label}[{index}] source"),
            _authority_ref(edge[1], f"{label}[{index}] target"),
        )
        if source not in residue_set or target not in residue_set:
            raise ValueError(f"{label} edge endpoints must belong to the residue")
        edges.append((source, target))
    result = tuple(edges)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must be unique")
    if result != tuple(sorted(result, key=lambda edge: (_structural_key(edge[0]), _structural_key(edge[1])))):
        raise ValueError(f"{label} must be in canonical order")
    return result


def _terminal_cycle_exists(
    residue: tuple[NativeBlockRef | LogicalBlockRef, ...],
    edges: tuple[tuple[NativeBlockRef | LogicalBlockRef, NativeBlockRef | LogicalBlockRef], ...],
) -> bool:
    successors = {ref: set() for ref in residue}
    for source, target in edges:
        successors[source].add(target)
    active: set[NativeBlockRef | LogicalBlockRef] = set()
    complete: set[NativeBlockRef | LogicalBlockRef] = set()

    def visit(ref: NativeBlockRef | LogicalBlockRef) -> bool:
        if ref in active:
            return True
        if ref in complete:
            return False
        active.add(ref)
        if any(visit(target) for target in successors[ref]):
            return True
        active.remove(ref)
        complete.add(ref)
        return False

    return any(visit(ref) for ref in residue)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class TerminalCyclePhaseResult:
    """One transaction-owned terminal-cycle binding result for a phase."""

    result_id: str
    claim_id: str
    terminal_route_proof_id: str
    phase: UnflattenAuthorityPhase
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    bound_subject_ids: tuple[str, ...]
    source_binding_digest: str
    candidate_binding_digest: str
    residue_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    source_cycle_edges: tuple[tuple[NativeBlockRef | LogicalBlockRef, NativeBlockRef | LogicalBlockRef], ...]
    candidate_cycle_edges: tuple[tuple[NativeBlockRef | LogicalBlockRef, NativeBlockRef | LogicalBlockRef], ...]
    source_bindings: tuple[PhaseSubjectBinding, ...]
    candidate_bindings: tuple[PhaseSubjectBinding, ...]
    terminal_source_ref: NativeBlockRef | LogicalBlockRef
    cleanup_source_ref: NativeBlockRef | LogicalBlockRef
    terminal_carrier_ref: NativeBlockRef | LogicalBlockRef
    terminal_route_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    terminal_subject_id: str
    terminal_subject_ref: NativeBlockRef | LogicalBlockRef

    def __post_init__(self) -> None:
        _id(self.result_id, "result_id")
        _id(self.claim_id, "claim_id")
        _id(self.terminal_route_proof_id, "terminal_route_proof_id")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        bound_subject_ids = _strict_id_tuple(self.bound_subject_ids, "bound_subject_ids")
        object.__setattr__(self, "bound_subject_ids", bound_subject_ids)
        _id(self.source_binding_digest, "source_binding_digest")
        _id(self.candidate_binding_digest, "candidate_binding_digest")
        residue = _terminal_cycle_refs(self.residue_refs, "residue_refs")
        object.__setattr__(self, "residue_refs", residue)
        source_edges = _terminal_cycle_edges(self.source_cycle_edges, "source_cycle_edges", residue)
        candidate_edges = _terminal_cycle_edges(self.candidate_cycle_edges, "candidate_cycle_edges", residue)
        if not _terminal_cycle_exists(residue, source_edges):
            raise ValueError("source cycle edges must contain a directed cycle")
        if _terminal_cycle_exists(residue, candidate_edges):
            raise ValueError("candidate cycle edges must be acyclic")
        object.__setattr__(self, "source_cycle_edges", source_edges)
        object.__setattr__(self, "candidate_cycle_edges", candidate_edges)
        for name in ("source_bindings", "candidate_bindings"):
            bindings = getattr(self, name)
            if type(bindings) is not tuple or any(type(item) is not PhaseSubjectBinding for item in bindings):
                raise TypeError(f"{name} must contain PhaseSubjectBinding values")
            if tuple(sorted(bindings, key=lambda item: item.subject.subject_id)) != bindings:
                raise ValueError(f"{name} must be in canonical subject order")
            if tuple(item.subject.subject_id for item in bindings) != bound_subject_ids:
                raise ValueError(f"{name} must exactly cover bound_subject_ids")
        if any(
            item.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST
            or item.graph_fingerprint != self.source_fingerprint
            or item.generation != self.source_generation
            for item in self.source_bindings
        ):
            raise ValueError("source bindings do not match terminal-cycle source coordinates")
        if any(
            item.phase is not self.phase
            or item.graph_fingerprint != self.candidate_fingerprint
            or item.generation != self.candidate_generation
            for item in self.candidate_bindings
        ):
            raise ValueError("candidate bindings do not match terminal-cycle candidate coordinates")
        if self.source_binding_digest != authority_id(self.source_bindings):
            raise ValueError("source_binding_digest does not match source_bindings")
        if self.candidate_binding_digest != authority_id(self.candidate_bindings):
            raise ValueError("candidate_binding_digest does not match candidate_bindings")
        for name in ("terminal_source_ref", "cleanup_source_ref", "terminal_carrier_ref", "terminal_subject_ref"):
            _authority_ref(getattr(self, name), name)
        if self.cleanup_source_ref not in residue:
            raise ValueError("cleanup_source_ref must belong to residue_refs")
        if type(self.terminal_route_refs) is not tuple:
            raise TypeError("terminal_route_refs must be an exact tuple")
        route = tuple(
            _authority_ref(value, "terminal_route_refs item")
            for value in self.terminal_route_refs
        )
        if not route or len(set(route)) != len(route):
            raise ValueError("terminal_route_refs must be non-empty and unique")
        if route[0] != self.terminal_carrier_ref:
            raise ValueError("terminal route must begin at terminal_carrier_ref")
        if route[-1] != self.terminal_subject_ref:
            raise ValueError("terminal route must end at terminal_subject_ref")
        object.__setattr__(self, "terminal_route_refs", route)
        _id(self.terminal_subject_id, "terminal_subject_id")
        if self.terminal_subject_id not in bound_subject_ids:
            raise ValueError("terminal subject must be one of the bound subjects")
        if self.result_id != authority_id((
            "unflatten.terminal-cycle-phase.v1", self.claim_id,
            self.terminal_route_proof_id, self.phase, self.source_fingerprint,
            self.candidate_fingerprint, self.source_generation,
            self.candidate_generation, self.bound_subject_ids,
            self.source_binding_digest, self.candidate_binding_digest,
            self.residue_refs, self.source_cycle_edges,
            self.candidate_cycle_edges, self.terminal_source_ref,
            self.cleanup_source_ref, self.terminal_carrier_ref,
            self.terminal_route_refs, self.terminal_subject_id,
            self.terminal_subject_ref,
        )):
            raise ValueError("result_id does not match canonical terminal-cycle phase result content")


@dataclass(frozen=True, slots=True)
class TerminalCycleEvidencePayload:
    """Evidence payload that carries one exact terminal-cycle phase result."""

    phase_result_id: str
    claim_id: str
    terminal_route_proof_id: str
    phase: UnflattenAuthorityPhase
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    bound_subject_ids: tuple[str, ...]
    source_binding_digest: str
    candidate_binding_digest: str
    residue_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    source_cycle_edges: tuple[tuple[NativeBlockRef | LogicalBlockRef, NativeBlockRef | LogicalBlockRef], ...]
    candidate_cycle_edges: tuple[tuple[NativeBlockRef | LogicalBlockRef, NativeBlockRef | LogicalBlockRef], ...]
    source_bindings: tuple[PhaseSubjectBinding, ...]
    candidate_bindings: tuple[PhaseSubjectBinding, ...]
    terminal_source_ref: NativeBlockRef | LogicalBlockRef
    cleanup_source_ref: NativeBlockRef | LogicalBlockRef
    terminal_carrier_ref: NativeBlockRef | LogicalBlockRef
    terminal_route_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    terminal_subject_id: str
    terminal_subject_ref: NativeBlockRef | LogicalBlockRef

    def __post_init__(self) -> None:
        result = TerminalCyclePhaseResult(
            self.phase_result_id, self.claim_id, self.terminal_route_proof_id,
            self.phase, self.source_fingerprint, self.candidate_fingerprint,
            self.source_generation, self.candidate_generation,
            self.bound_subject_ids, self.source_binding_digest,
            self.candidate_binding_digest, self.residue_refs,
            self.source_cycle_edges, self.candidate_cycle_edges,
            self.source_bindings, self.candidate_bindings,
            self.terminal_source_ref, self.cleanup_source_ref,
            self.terminal_carrier_ref, self.terminal_route_refs,
            self.terminal_subject_id, self.terminal_subject_ref,
        )
        object.__setattr__(self, "phase_result_id", result.result_id)


def _validate_terminal_cycle_phase_results(
    results: object,
    claims: tuple[UnflattenClaim, ...],
    *,
    phase: UnflattenAuthorityPhase,
    source_fingerprint: str,
    candidate_fingerprint: str,
    source_generation: int,
    candidate_generation: int,
    expected_source_bindings: tuple[PhaseSubjectBinding, ...],
    expected_candidate_bindings: tuple[PhaseSubjectBinding, ...],
    source_inventory: SemanticGraphInventory,
    candidate_inventory: SemanticGraphInventory,
) -> tuple[TerminalCyclePhaseResult, ...]:
    if type(results) is not tuple:
        raise TypeError("terminal_cycle_phase_results must be an exact tuple")
    values = tuple(results)
    if any(type(value) is not TerminalCyclePhaseResult for value in values):
        raise TypeError("terminal_cycle_phase_results must contain closed results")
    if values != tuple(sorted(values, key=lambda item: item.result_id)):
        raise ValueError("terminal_cycle_phase_results must be in canonical result order")
    terminal_claims = tuple(
        claim for claim in claims if type(claim) is TerminalCycleBreakClaim
    )
    if len(values) != len(terminal_claims):
        raise ValueError("there must be exactly one terminal-cycle phase result per claim")
    claim_by_id = {claim.claim_id: claim for claim in terminal_claims}
    if len(claim_by_id) != len(terminal_claims):
        raise ValueError("terminal-cycle claims must have unique IDs")
    from .bind import validate_terminal_cycle_phase_result
    for result in values:
        result.__post_init__()
        validate_terminal_cycle_phase_result(result)
        claim = claim_by_id.get(result.claim_id)
        if claim is None:
            raise ValueError("terminal-cycle phase result claim is foreign")
        if (
            result.terminal_route_proof_id not in claim.terminal_route_proof_ids
            or result.phase is not phase
            or result.source_fingerprint != source_fingerprint
            or result.candidate_fingerprint != candidate_fingerprint
            or result.source_generation != source_generation
            or result.candidate_generation != candidate_generation
            or result.source_bindings != tuple(
                binding for binding in expected_source_bindings
                if binding.subject.subject_id in set(result.bound_subject_ids)
            )
            or result.candidate_bindings != tuple(
                binding for binding in expected_candidate_bindings
                if binding.subject.subject_id in set(result.bound_subject_ids)
            )
        ):
            raise ValueError("terminal-cycle phase result coordinates are not sealed")
        cycle = claim.cycle_subject.locator
        cleanup = claim.cleanup_source_subject.locator
        terminal = claim.terminal_subject.locator
        if (
            type(cycle) is not CorridorSubjectLocator
            or type(cleanup) is not BlockSubjectLocator
            or type(terminal) not in (
                TerminalSubjectLocator,
                LogicalFunctionExitSubjectLocator,
            )
        ):
            raise ValueError("terminal-cycle claim locators are not closed")
        if (
            result.residue_refs != cycle.member_refs
            or result.cleanup_source_ref != cleanup.block_ref
            or result.terminal_subject_id != claim.terminal_subject.subject_id
            or result.terminal_subject_ref != terminal.block_ref
            or not {
                claim.cycle_subject.subject_id,
                claim.cleanup_source_subject.subject_id,
                claim.terminal_subject.subject_id,
            } <= set(result.bound_subject_ids)
        ):
            raise ValueError("terminal-cycle phase result does not match claim subjects")
        _validate_terminal_cycle_phase_result_inventories(
            result, claim, source_inventory, candidate_inventory,
        )
    return values


def _validate_terminal_cycle_evidence(
    results: tuple[TerminalCyclePhaseResult, ...],
    evidence: tuple[AuthorityEvidence, ...],
    claims: tuple[UnflattenClaim, ...],
    phase: UnflattenAuthorityPhase,
) -> None:
    """Require a bijective, case-owned evidence row for each phase result."""

    terminal_rows = tuple(
        item for item in evidence
        if item.kind is AuthorityEvidenceKind.TERMINAL_CYCLE
    )
    if len(terminal_rows) != len(results):
        raise ValueError(
            "terminal-cycle evidence must be bijective with phase results"
        )
    rows_by_result_id = {
        item.payload.phase_result_id: item for item in terminal_rows
    }
    if len(rows_by_result_id) != len(terminal_rows):
        raise ValueError("terminal-cycle evidence contains duplicate phase results")
    result_by_id = {result.result_id: result for result in results}
    if set(rows_by_result_id) != set(result_by_id):
        raise ValueError(
            "terminal-cycle evidence contains a foreign or missing phase result"
        )
    claims_by_id = {
        claim.claim_id: claim
        for claim in claims
        if type(claim) is TerminalCycleBreakClaim
    }
    for result in results:
        row = rows_by_result_id[result.result_id]
        claim = claims_by_id.get(result.claim_id)
        if claim is None:
            raise ValueError("terminal-cycle evidence claim is foreign")
        expected_payload = TerminalCycleEvidencePayload(
            result.result_id, result.claim_id, result.terminal_route_proof_id,
            result.phase, result.source_fingerprint, result.candidate_fingerprint,
            result.source_generation, result.candidate_generation,
            result.bound_subject_ids, result.source_binding_digest,
            result.candidate_binding_digest, result.residue_refs,
            result.source_cycle_edges, result.candidate_cycle_edges,
            result.source_bindings, result.candidate_bindings,
            result.terminal_source_ref, result.cleanup_source_ref,
            result.terminal_carrier_ref, result.terminal_route_refs,
            result.terminal_subject_id, result.terminal_subject_ref,
        )
        if (
            row.phase is not phase
            or row.subject != claim.cycle_subject
            or row.payload != expected_payload
        ):
            raise ValueError(
                "terminal-cycle evidence does not match case-owned phase result"
            )


SemanticSubjectLocator: TypeAlias = (
    BlockSubjectLocator | LogicalFunctionExitSubjectLocator | EdgeSubjectLocator | RouteSubjectLocator
    | EffectSubjectLocator | HandlerSubjectLocator | TerminalSubjectLocator
    | ValueFlowSubjectLocator | CorridorSubjectLocator
)


_SUBJECT_MATRIX = {
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SOURCE_CATALOG_BLOCK): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SOURCE_LOGICAL_EXIT): LogicalFunctionExitSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SOURCE_ENTRY): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_ENTRY): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.DETACHED_DEAD_HANDLER_COMPONENT): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT): LogicalFunctionExitSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_SOURCE): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_PREDICATE): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_SELECTED_TARGET): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_DISCARDED_OWNER): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.DEFAULT_GAP_INFEASIBLE_RESIDUAL): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.EFFECT_SITE): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.PLANNED_HELPER): BlockSubjectLocator,
    (SemanticSubjectKind.EDGE, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): EdgeSubjectLocator,
    (SemanticSubjectKind.ROUTE, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): RouteSubjectLocator,
    (SemanticSubjectKind.EFFECT, SemanticSubjectRole.EFFECT_SITE): EffectSubjectLocator,
    (SemanticSubjectKind.HANDLER, SemanticSubjectRole.AUTHORITATIVE_HANDLER): HandlerSubjectLocator,
    (SemanticSubjectKind.TERMINAL, SemanticSubjectRole.TERMINAL_SITE): (
        TerminalSubjectLocator,
        LogicalFunctionExitSubjectLocator,
    ),
    (SemanticSubjectKind.VALUE_FLOW, SemanticSubjectRole.NON_STATE_VALUE_FLOW): ValueFlowSubjectLocator,
    (SemanticSubjectKind.CORRIDOR, SemanticSubjectRole.DISPATCHER_CORRIDOR): CorridorSubjectLocator,
}


def _subject_owner(locator: SemanticSubjectLocator) -> tuple[CfgBlockRef | None, int | None]:
    if isinstance(locator, BlockSubjectLocator):
        return locator.block_ref, locator.anchor_ea
    if isinstance(locator, LogicalFunctionExitSubjectLocator):
        return locator.block_ref, None
    if isinstance(locator, EdgeSubjectLocator):
        return locator.source_ref, locator.source_anchor_ea
    if isinstance(locator, RouteSubjectLocator):
        return locator.source_ref, locator.source_anchor_ea
    if isinstance(locator, EffectSubjectLocator):
        return locator.owner_ref, locator.owner_anchor_ea
    if isinstance(locator, HandlerSubjectLocator):
        return locator.block_ref, locator.anchor_ea
    if isinstance(locator, TerminalSubjectLocator):
        return locator.block_ref, locator.anchor_ea
    if isinstance(locator, CorridorSubjectLocator):
        return locator.entry_ref, locator.entry_anchor_ea
    return None, None


@dataclass(frozen=True, slots=True)
class SemanticSubjectRef:
    kind: SemanticSubjectKind
    role: SemanticSubjectRole
    subject_id: str
    block_ref: CfgBlockRef | None
    anchor_ea: int | None
    locator: SemanticSubjectLocator

    def __post_init__(self) -> None:
        _enum(self.kind, SemanticSubjectKind, "kind")
        _enum(self.role, SemanticSubjectRole, "role")
        _id(self.subject_id, "subject_id")
        expected = _SUBJECT_MATRIX.get((self.kind, self.role))
        expected_types = expected if type(expected) is tuple else (expected,)
        if expected is None or type(self.locator) not in expected_types:
            raise ValueError("unsupported subject kind/role/locator")
        if type(self.block_ref) not in _CFG_REF_TYPES and self.block_ref is not None:
            raise TypeError("block_ref must be a CfgBlockRef or None")
        if self.role is SemanticSubjectRole.SOURCE_CATALOG_BLOCK and type(self.block_ref) not in {
            NativeBlockRef, LogicalBlockRef,
        }:
            raise ValueError("source catalog blocks require a source-authority block reference")
        if self.role is SemanticSubjectRole.PLANNED_HELPER and type(self.block_ref) is not PlanBlockRef:
            raise ValueError("planned helpers require a PlanBlockRef")
        if self.anchor_ea is not None:
            _ea(self.anchor_ea, "anchor_ea")
        owner, owner_ea = _subject_owner(self.locator)
        if self.kind is SemanticSubjectKind.VALUE_FLOW:
            if self.block_ref is not None or self.anchor_ea is not None:
                raise ValueError("value-flow subjects have no primary owner")
        elif self.block_ref != owner or self.anchor_ea != owner_ea:
            raise ValueError("subject primary owner must match locator")
        if self.subject_id != _subject_id_from_record(self):
            raise ValueError("subject_id does not match canonical subject content")


@dataclass(frozen=True, slots=True)
class PhaseSubjectBinding:
    subject: SemanticSubjectRef
    phase: UnflattenAuthorityPhase
    block_ref: CfgBlockRef | None
    graph_fingerprint: str
    generation: int
    status: SubjectBindingStatus
    serial: int | None
    anchor_ea: int | None
    native_instruction_eas: tuple[int, ...]
    role: SemanticSubjectRole
    observed_logical_occurrence: ObservedLogicalEndpointOccurrence | None = None

    def __post_init__(self) -> None:
        if type(self.subject) is not SemanticSubjectRef:
            raise TypeError("subject must be a SemanticSubjectRef")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        if self.block_ref is not None:
            _cfg_ref(self.block_ref)
        _id(self.graph_fingerprint, "graph_fingerprint")
        _generation(self.generation)
        _enum(self.status, SubjectBindingStatus, "status")
        _enum(self.role, SemanticSubjectRole, "role")
        if self.role is not self.subject.role:
            raise ValueError("binding role must equal subject role")
        eas = _tuple(self.native_instruction_eas, "native_instruction_eas", sort=True)
        for ea in eas:
            _ea(ea, "native_instruction_eas item")
        object.__setattr__(self, "native_instruction_eas", eas)
        if self.serial is not None:
            _nonnegative(self.serial, "serial")
        if self.anchor_ea is not None:
            _ea(self.anchor_ea, "anchor_ea")
        occurrence = self.observed_logical_occurrence
        if occurrence is not None:
            if type(occurrence) is not ObservedLogicalEndpointOccurrence:
                raise TypeError(
                    "observed_logical_occurrence has an unknown type",
                )
            occurrence.__post_init__()
        if self.status is SubjectBindingStatus.UNIQUE:
            if self.subject.block_ref is None or self.block_ref != self.subject.block_ref:
                raise ValueError("unique binding requires block_ref")
            if self.serial is None:
                raise ValueError("unique binding requires serial, anchor, and native EAs")
            if type(self.subject.locator) is LogicalFunctionExitSubjectLocator:
                if (
                    self.anchor_ea is not None
                    or eas
                ):
                    raise ValueError("logical function-exit binding must remain anchorless")
                moved = self.serial != self.subject.locator.serial
                if moved != (
                    self.phase is UnflattenAuthorityPhase.OBSERVED_POST_APPLY
                    and occurrence is not None
                ):
                    raise ValueError(
                        "logical function-exit serial movement requires one "
                        "observed occurrence",
                    )
                if occurrence is not None and (
                    occurrence.logical_ref != self.block_ref
                    or occurrence.projected_serial
                    != self.subject.locator.serial
                    or occurrence.observed_serial != self.serial
                ):
                    raise ValueError(
                        "logical function-exit occurrence differs from binding",
                    )
                return
            if occurrence is not None:
                raise ValueError(
                    "only a moved logical endpoint may carry an observed occurrence",
                )
            if self.anchor_ea is None:
                raise ValueError("unique binding requires serial, anchor, and native EAs")
            if self.anchor_ea != self.subject.anchor_ea:
                raise ValueError("unique binding anchor must equal subject anchor")
            if not _anchor_matches_native_scope(
                self.block_ref, self.anchor_ea, eas,
            ):
                raise ValueError(
                    "unique binding anchor must belong to native scope"
                )
        elif (
            self.block_ref is not None
            or self.serial is not None
            or self.anchor_ea is not None
            or eas
            or occurrence is not None
        ):
            raise ValueError("non-unique binding requires no block, serial, anchor, or native EAs")


@dataclass(frozen=True, slots=True)
class PhaseBindingEvidencePayload:
    binding: PhaseSubjectBinding

    def __post_init__(self) -> None:
        if type(self.binding) is not PhaseSubjectBinding:
            raise TypeError("binding must be a PhaseSubjectBinding")


def _inventory_nonnegative(value: object, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if value < 0:
        raise ValueError(f"{label} must not be negative")
    return value


def _inventory_ea(value: object, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")
    if not 0 <= value < _BADADDR:
        raise ValueError(f"{label} must be a native EA")
    return value


def _is_unowned_structural_stop_row(row: object) -> bool:
    """Whether an inventory row is the instructionless synthetic STOP."""

    return (
        getattr(row, "block_ref", object()) is None
        and getattr(row, "block_kind", None) is BlockKind.STOP
        and getattr(row, "anchor_ea", object()) is None
        and not getattr(row, "native_instruction_eas", ())
        and not getattr(row, "instruction_observations", ())
        and not getattr(row, "successor_serials", ())
        and getattr(row, "transfer_ea", object()) is None
        and getattr(row, "graph_start_ea", _BADADDR) == _BADADDR
    )


def _is_exact_logical_function_exit_row(row: object) -> bool:
    """Recognize the one owned, anchorless logical function-exit row.

    A function exit is a real source coordinate for a logical decision-DAG
    endpoint, but it deliberately has no native anchor.  Keep it in the
    transaction inventory so the source authority can bind its full logical
    reference identity exactly once.
    """

    return is_exact_logical_function_exit_inventory_row_shape(
        row,
        logical_block_ref_type=LogicalBlockRef,
    )


def _claimed_logical_function_exit_coordinates(
    proposal: object,
) -> frozenset[tuple[LogicalBlockRef, int]]:
    """Return only exact logical exits owned by typed route or terminal claims.

    Logical source rows intentionally sit outside the native identity catalog.
    They are admissible only where an immutable claim names the exact
    ``LogicalFunctionExitSubjectLocator``; this keeps a terminal-cycle stop
    equivalent to a selected DAG endpoint without admitting arbitrary logical
    coordinates from a patch plan.
    """
    coordinates: set[tuple[LogicalBlockRef, int]] = set()
    for claim in getattr(proposal, "claims", ()):
        if type(claim) is EquivalentSemanticRouteClaim:
            subjects = claim.dag_endpoint_subjects
        elif type(claim) is TerminalCycleBreakClaim:
            subjects = (claim.terminal_subject,)
        else:
            continue
        for subject in subjects:
            locator = subject.locator
            if type(locator) is LogicalFunctionExitSubjectLocator:
                coordinates.add((locator.block_ref, locator.serial))
    return frozenset(coordinates)


def is_exact_logical_function_exit_inventory_row(row: object) -> bool:
    """Public authority predicate for the one anchorless DAG endpoint row."""
    return _is_exact_logical_function_exit_row(row)


def _validate_native_identity_primitives(identity: object, label: str) -> None:
    """Check native identity scalars before any normalizing post-init runs.

    ``StableBlockIdentity`` and its interval/key children historically coerce
    values (notably ``int(True)`` and interval iterables) in ``__post_init__``.
    Inventory records are an authority boundary, so a caller-owned frozen
    evidence graph must be rejected in its corrupted form rather than
    normalized in place before it is inspected.
    """

    if type(identity) is not StableBlockIdentity:
        raise TypeError(f"{label}.identity must be a StableBlockIdentity")
    key = identity.native_key
    if type(key) is not NativePreanalysisKey:
        raise TypeError(f"{label}.identity.native_key must be a NativePreanalysisKey")
    for field_name in (
        "input_identity",
        "processor",
        "function_fingerprint",
        "profile_fingerprint",
        "sdk_fingerprint",
    ):
        value = getattr(key, field_name)
        if type(value) is not str:
            raise TypeError(f"{label}.{field_name} must be an exact string")
        if not value.strip() or value != value.strip():
            raise ValueError(f"{label}.{field_name} must be canonical and non-blank")
    for field_name in ("bitness", "function_rva"):
        value = getattr(key, field_name)
        if type(value) is not int:
            raise TypeError(f"{label}.{field_name} must be an exact int")
    if key.bitness not in {16, 32, 64}:
        raise ValueError(f"{label}.bitness must be one of 16, 32, or 64")
    if key.function_rva < 0:
        raise ValueError(f"{label}.function_rva must not be negative")
    ranges = identity.native_ranges
    if type(ranges) is not NativeEaIntervalSet:
        raise TypeError(f"{label}.native_ranges must be a NativeEaIntervalSet")
    if type(ranges.intervals) is not tuple:
        raise TypeError(f"{label}.native_ranges.intervals must be an exact tuple")
    previous: NativeEaInterval | None = None
    for index, interval in enumerate(ranges.intervals):
        interval_label = f"{label}.native_ranges.intervals[{index}]"
        if type(interval) is not NativeEaInterval:
            raise TypeError(f"{interval_label} must be a NativeEaInterval")
        if type(interval.start_ea) is not int or type(interval.end_ea) is not int:
            raise TypeError(f"{interval_label} endpoints must be exact ints")
        if (
            interval.start_ea < 0
            or interval.start_ea >= _BADADDR
            or interval.end_ea <= interval.start_ea
            or interval.end_ea > _BADADDR
        ):
            raise ValueError(f"{interval_label} must be a bounded native range")
        if previous is not None and interval.start_ea <= previous.end_ea:
            raise ValueError(f"{label}.native_ranges must be canonical and disjoint")
        previous = interval
    if not ranges.intervals:
        raise ValueError(f"{label}.native_ranges must not be empty")

    exact_eas = identity.exact_instruction_eas
    if type(exact_eas) is not frozenset:
        raise TypeError(f"{label}.exact_instruction_eas must be an exact frozenset")
    for index, ea in enumerate(exact_eas):
        _inventory_ea(ea, f"{label}.exact_instruction_eas[{index}]")
        if not ranges.contains(ea):
            raise ValueError(f"{label}.exact_instruction_eas must belong to native ranges")

    # Every primitive in the nested graph is now known to be exact and
    # canonical, so rerunning the normal validators cannot coerce or mutate a
    # caller-owned corrupted value before it has been rejected.
    key.__post_init__()


def _validate_inventory_refs(value: object, *, producer: bool, label: str) -> None:
    if type(value) in _CFG_REF_TYPES:
        if producer and type(value) is PlanBlockRef:
            raise TypeError(f"{label} may not use PlanBlockRef in producer phase")
        if type(value) is NativeBlockRef:
            _validate_native_identity_primitives(value.identity, f"{label}.identity")
        value.__post_init__()
        validate_canonical_roundtrip(value, type(value))
        return
    if type(value) is tuple:
        for index, item in enumerate(value):
            _validate_inventory_refs(item, producer=producer, label=f"{label}[{index}]")
        return
    if is_dataclass(value) and not isinstance(value, type):
        for item in fields(value):
            if item.name.startswith("_"):
                continue
            _validate_inventory_refs(
                getattr(value, item.name), producer=producer,
                label=f"{label}.{item.name}",
            )
        post_init = getattr(value, "__post_init__", None)
        if post_init is not None:
            post_init()


@dataclass(frozen=True, slots=True)
class InventoryPredicateObservation:
    """Closed predicate facts retained for one projected conditional tail."""

    predicate_kind: PredicateKind
    storage_identity: StorageIdentity
    width: int
    compare_constant: int
    explicit_target_serial: int

    def __post_init__(self) -> None:
        if type(self.predicate_kind) is not PredicateKind:
            raise TypeError("predicate_kind must be PredicateKind")
        if type(self.storage_identity) is not StorageIdentity:
            raise TypeError("storage_identity must be StorageIdentity")
        if type(self.width) is not int or isinstance(self.width, bool) or self.width <= 0:
            raise ValueError("predicate width must be a positive exact int")
        if type(self.compare_constant) is not int or isinstance(self.compare_constant, bool):
            raise TypeError("compare_constant must be an exact int")
        if not 0 <= self.compare_constant < (1 << (self.width * 8)):
            raise ValueError("compare_constant does not fit predicate width")
        _inventory_nonnegative(self.explicit_target_serial, "explicit_target_serial")


@dataclass(frozen=True, slots=True)
class InventoryInstructionObservation:
    ordinal: int
    instruction_ea: int | None
    opcode: int
    width: int
    instruction_kind: InsnKind
    control_transfer_kind: ControlTransferKind | None
    is_call: bool
    call_kind: CallKind | None
    display_text: str | None = None
    predicate_observation: InventoryPredicateObservation | None = None
    raw_opcode: int | None = None

    def __post_init__(self) -> None:
        _inventory_nonnegative(self.ordinal, "ordinal")
        if self.instruction_ea is not None:
            _inventory_ea(self.instruction_ea, "instruction_ea")
        if type(self.opcode) is not int:
            raise TypeError("opcode must be an exact int")
        if self.opcode < 0:
            if self.opcode != -1:
                raise ValueError("synthetic opcode must be the normalized GOTO sentinel")
            if self.raw_opcode is not None:
                raise ValueError("normalized synthetic GOTO cannot carry raw opcode")
            if (
                self.instruction_kind is not InsnKind.GOTO
                or self.control_transfer_kind is not ControlTransferKind.GOTO
                or self.is_call
                or self.call_kind is not None
                or self.predicate_observation is not None
            ):
                raise ValueError("raw opcode absence is reserved for normalized synthetic GOTO")
        elif self.raw_opcode is None:
            raise ValueError("backend instruction requires exact raw opcode")
        elif type(self.raw_opcode) is not int:
            raise TypeError("raw_opcode must be an exact int")
        _inventory_nonnegative(self.width, "width")
        if type(self.instruction_kind) is not InsnKind:
            raise TypeError("instruction_kind must be InsnKind")
        if self.control_transfer_kind is not None and type(self.control_transfer_kind) is not ControlTransferKind:
            raise TypeError("control_transfer_kind must be ControlTransferKind or None")
        if type(self.is_call) is not bool:
            raise TypeError("is_call must be an exact bool")
        if self.call_kind is not None and type(self.call_kind) is not CallKind:
            raise TypeError("call_kind must be CallKind or None")
        if self.display_text is not None and type(self.display_text) is not str:
            raise TypeError("display_text must be an exact string or None")
        if self.predicate_observation is not None:
            if type(self.predicate_observation) is not InventoryPredicateObservation:
                raise TypeError("predicate_observation must be InventoryPredicateObservation or None")
            self.predicate_observation.__post_init__()


def required_inventory_control_transfer(
    instruction_kind: InsnKind,
) -> ControlTransferKind | None:
    """Return the transfer marker required by a raw instruction kind.

    ``InsnSnapshot.__post_init__`` normally fills these markers.  Inventory
    observations and producer snapshots can nevertheless be corrupted after
    construction, so the authority resolver must validate the correlation
    rather than trusting a possibly erased derived field.  UNKNOWN remains
    intentionally open because recovery adapters may supply a semantic marker
    without a recognized raw kind.
    """

    if type(instruction_kind) is not InsnKind:
        raise TypeError("instruction_kind must be InsnKind")
    return {
        InsnKind.GOTO: ControlTransferKind.GOTO,
        InsnKind.COND_JUMP: ControlTransferKind.CONDITIONAL_BRANCH,
        InsnKind.EQUALITY_JUMP: ControlTransferKind.CONDITIONAL_BRANCH,
        InsnKind.TABLE_JUMP: ControlTransferKind.TABLE_BRANCH,
        InsnKind.INDIRECT_JUMP: ControlTransferKind.INDIRECT_BRANCH,
        InsnKind.RET: ControlTransferKind.RETURN,
    }.get(instruction_kind)


def validate_inventory_control_transfer(
    instruction_kind: InsnKind,
    control_transfer_kind: ControlTransferKind | None,
) -> None:
    """Enforce the closed raw-kind/control-marker correlation.

    UNKNOWN is the sole recovery escape hatch: adapters may retain a semantic
    transfer marker when the raw kind is unavailable. Every other known kind is
    either a transfer family requiring its exact marker or a non-control kind
    requiring no marker at all.
    """

    if type(instruction_kind) is not InsnKind:
        raise TypeError("instruction_kind must be InsnKind")
    if control_transfer_kind is not None and type(control_transfer_kind) is not ControlTransferKind:
        raise TypeError("control_transfer_kind must be ControlTransferKind or None")
    if instruction_kind is InsnKind.UNKNOWN:
        return
    required_transfer = required_inventory_control_transfer(instruction_kind)
    if required_transfer is not None:
        if control_transfer_kind is not required_transfer:
            raise ValueError(
                f"{instruction_kind.value} requires control transfer "
                f"{required_transfer.value}"
            )
        return
    if control_transfer_kind is not None:
        raise ValueError(
            f"{instruction_kind.value} must not carry control transfer "
            f"{control_transfer_kind.value}"
        )


def resolve_inventory_instruction(
    observation: InventoryInstructionObservation,
    *,
    is_tail: bool,
    has_successors: bool,
) -> tuple[EffectSiteKind | None, TerminalKind | None]:
    """Resolve one raw instruction observation into its semantic catalogs."""
    if type(observation) is not InventoryInstructionObservation:
        raise TypeError("instruction observation must be nominal")
    observation.__post_init__()
    if type(is_tail) is not bool or type(has_successors) is not bool:
        raise TypeError("resolver context booleans must be exact bools")
    validate_inventory_control_transfer(
        observation.instruction_kind, observation.control_transfer_kind,
    )
    is_store = observation.instruction_kind is InsnKind.STORE
    is_trap = observation.instruction_kind is InsnKind.TRAP
    is_return = (
        observation.instruction_kind is InsnKind.RET
        or observation.control_transfer_kind is ControlTransferKind.RETURN
    )
    is_call = (
        observation.instruction_kind is InsnKind.CALL
        or observation.is_call
        or observation.call_kind is not None
    )
    matches = sum((is_store, is_trap, is_return, is_call))
    if matches > 1:
        raise ValueError("instruction effect semantics overlap")
    if matches == 0:
        return None, None
    if observation.instruction_ea is None:
        raise ValueError("required effect has no valid native instruction EA")
    effect_kind = (
        EffectSiteKind.STORE if is_store else
        EffectSiteKind.TRAP if is_trap else
        EffectSiteKind.RETURN if is_return else EffectSiteKind.CALL
    )
    terminal_kind = (
        TerminalKind.TRAP if is_trap else
        TerminalKind.RETURN if is_return else
        TerminalKind.NORETURN_CALL if is_call and is_tail and not has_successors else None
    )
    return effect_kind, terminal_kind


def resolve_inventory_block_sites(
    *,
    serial: int,
    owner_ref: CfgBlockRef | None,
    owner_anchor_ea: int,
    block_kind: BlockKind,
    successor_serials: tuple[int, ...],
    instruction_observations: tuple[InventoryInstructionObservation, ...],
) -> tuple[tuple[InventoryEffectSite, ...], tuple[InventoryTerminalSite, ...]]:
    """Resolve one block's raw rows into exact effect and terminal sites."""
    _inventory_nonnegative(serial, "serial")
    _inventory_ea(owner_anchor_ea, "owner_anchor_ea")
    if owner_ref is not None and type(owner_ref) not in _CFG_REF_TYPES:
        raise TypeError("owner_ref must be an exact CfgBlockRef or None")
    if owner_ref is not None:
        _validate_inventory_refs(owner_ref, producer=False, label="owner_ref")
    if type(block_kind) is not BlockKind or type(successor_serials) is not tuple:
        raise TypeError("block resolver context is malformed")
    if len(set(successor_serials)) != len(successor_serials):
        raise ValueError("successor serials must be unique")
    for successor in successor_serials:
        _inventory_nonnegative(successor, "successor serial")
    if type(instruction_observations) is not tuple:
        raise TypeError("instruction observations must be an exact tuple")
    for observation in instruction_observations:
        if type(observation) is not InventoryInstructionObservation:
            raise TypeError("instruction observations must be nominal")
        observation.__post_init__()
    effects: list[InventoryEffectSite] = []
    terminals: list[InventoryTerminalSite] = []
    effect_keys: set[tuple[object, ...]] = set()
    terminal_keys: set[tuple[object, ...]] = set()
    for ordinal, observation in enumerate(instruction_observations):
        if observation.ordinal != ordinal:
            raise ValueError("instruction observations must be contiguous ordinal order")
        if observation.control_transfer_kind is not None and ordinal != len(instruction_observations) - 1:
            raise ValueError("control-transfer observations must be the block tail")
        effect_kind, terminal_kind = resolve_inventory_instruction(
            observation,
            is_tail=ordinal == len(instruction_observations) - 1,
            has_successors=bool(successor_serials),
        )
        if effect_kind is not None:
            effect = InventoryEffectSite(
                serial, owner_ref, owner_anchor_ea, ordinal, observation.instruction_ea,
                effect_kind, observation.opcode, observation.width,
            )
            key = (effect.owner_serial, effect.instruction_ea, effect.effect_kind)
            if key in effect_keys:
                raise ValueError("duplicate effect site")
            effect_keys.add(key)
            effects.append(effect)
        if terminal_kind is not None:
            terminal = InventoryTerminalSite(
                serial, owner_ref, owner_anchor_ea, ordinal, observation.instruction_ea,
                terminal_kind,
            )
            key = (terminal.owner_serial, terminal.instruction_ea, terminal.terminal_kind)
            if key in terminal_keys:
                raise ValueError("duplicate terminal site")
            terminal_keys.add(key)
            terminals.append(terminal)
    tail_terminal = bool(terminals and terminals[-1].instruction_ordinal == len(instruction_observations) - 1)
    if (
        block_kind is BlockKind.STOP
        and not tail_terminal
        and not (
            owner_ref is None
            and owner_anchor_ea == 0
            and not instruction_observations
        )
        and not (
            type(owner_ref) is LogicalBlockRef
            and owner_anchor_ea == 0
            and not instruction_observations
            and not successor_serials
        )
    ):
        terminal = InventoryTerminalSite(
            serial, owner_ref, owner_anchor_ea, None, owner_anchor_ea, TerminalKind.STOP,
        )
        key = (terminal.owner_serial, terminal.instruction_ea, terminal.terminal_kind)
        if key in terminal_keys:
            raise ValueError("duplicate terminal site")
        terminals.append(terminal)
    return tuple(effects), tuple(terminals)


@dataclass(frozen=True, slots=True)
class InventoryBlockObservation:
    serial: int
    block_ref: CfgBlockRef | None
    anchor_ea: int | None
    native_instruction_eas: tuple[int, ...]
    predecessor_serials: tuple[int, ...]
    successor_serials: tuple[int, ...]
    transfer_ea: int | None
    instruction_observations: tuple[InventoryInstructionObservation, ...] = ()
    block_kind: BlockKind = BlockKind.UNKNOWN
    graph_start_ea: int = _BADADDR
    tail_opcode: int | None = None
    raw_tail_opcode: int | None = None
    tail_kind: InsnKind | None = None

    def __post_init__(self) -> None:
        _inventory_nonnegative(self.serial, "serial")
        if self.block_ref is not None:
            _cfg_ref(self.block_ref)
        if type(self.block_kind) is not BlockKind:
            raise TypeError("block_kind must be BlockKind")
        if self.tail_opcode is not None and type(self.tail_opcode) is not int:
            raise TypeError("tail_opcode must be an exact int or None")
        if self.raw_tail_opcode is not None and type(self.raw_tail_opcode) is not int:
            raise TypeError("raw_tail_opcode must be an exact int or None")
        if self.tail_kind is not None and type(self.tail_kind) is not InsnKind:
            raise TypeError("tail_kind must be InsnKind or None")
        if type(self.graph_start_ea) is not int:
            raise TypeError("graph_start_ea must be an exact int")
        if not 0 <= self.graph_start_ea <= _BADADDR:
            raise ValueError("graph_start_ea must be a graph coordinate or BADADDR")
        if self.block_kind is BlockKind.STOP and self.anchor_ea is None and not (
            (
                self.block_ref is None
                and not self.native_instruction_eas
                and not self.instruction_observations
                and not self.successor_serials
                and self.graph_start_ea == _BADADDR
            )
            or _is_exact_logical_function_exit_row(self)
        ):
            raise ValueError("STOP observations require a resolved anchor EA")
        if self.anchor_ea is not None:
            _inventory_ea(self.anchor_ea, "anchor_ea")
        for name in ("native_instruction_eas", "predecessor_serials"):
            values = getattr(self, name)
            if type(values) is not tuple:
                raise TypeError(f"{name} must be an exact tuple")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must be unique")
            if values != tuple(sorted(values)):
                raise ValueError(f"{name} must be sorted")
            for value in values:
                if name == "native_instruction_eas":
                    _inventory_ea(value, f"{name} item")
                else:
                    _inventory_nonnegative(value, f"{name} item")
            object.__setattr__(self, name, values)
        successors = self.successor_serials
        if type(successors) is not tuple:
            raise TypeError("successor_serials must be an exact tuple")
        if len(set(successors)) != len(successors):
            raise ValueError("successor_serials must be unique")
        for value in successors:
            _inventory_nonnegative(value, "successor_serials item")
        object.__setattr__(self, "successor_serials", successors)
        if self.transfer_ea is not None:
            _inventory_ea(self.transfer_ea, "transfer_ea")
        if type(self.instruction_observations) is not tuple:
            raise TypeError("instruction_observations must be an exact tuple")
        if any(type(item) is not InventoryInstructionObservation for item in self.instruction_observations):
            raise TypeError("instruction_observations must contain exact rows")
        if self.instruction_observations:
            tail = self.instruction_observations[-1]
            if self.tail_opcode is None or self.tail_kind is None:
                raise ValueError("instruction-bearing blocks require complete tail metadata")
            if tail.opcode >= 0 and self.raw_tail_opcode is None:
                raise ValueError("backend tail requires exact raw opcode")
            if tail.opcode < 0 and self.raw_tail_opcode is not None:
                raise ValueError("normalized synthetic GOTO tail cannot carry raw opcode")
            if self.tail_opcode != tail.opcode:
                raise ValueError("tail_opcode must match the observed tail")
            if self.raw_tail_opcode != tail.raw_opcode:
                raise ValueError("raw_tail_opcode must match the observed tail")
            if self.tail_kind is not tail.instruction_kind:
                raise ValueError("tail_kind must match the observed tail")
            if tail.opcode == -1:
                # ``-1/raw=None`` is not a general missing-backend marker. It
                # is the one normalized synthetic helper vocabulary entry.
                # Close that shape here, before any inventory digest or ID can
                # be minted, rather than relying on producer/binder checks.
                if (
                    not self.instruction_observations
                    or self.block_kind is not BlockKind.ONE_WAY
                    or len(self.successor_serials) != 1
                    or tail.width != 0
                    or tail.display_text != ""
                    or self.transfer_ea != tail.instruction_ea
                    or tail.instruction_kind is not InsnKind.GOTO
                    or tail.control_transfer_kind is not ControlTransferKind.GOTO
                    or tail.is_call
                    or tail.call_kind is not None
                    or tail.predicate_observation is not None
                ):
                    raise ValueError("synthetic GOTO inventory shape is not normalized")
        elif any(value is not None for value in (self.tail_opcode, self.raw_tail_opcode, self.tail_kind)):
            raise ValueError("instructionless blocks cannot carry tail metadata")
        if tuple(item.ordinal for item in self.instruction_observations) != tuple(range(len(self.instruction_observations))):
            raise ValueError("instruction observations must be contiguous ordinal order")
        observed_eas = {item.instruction_ea for item in self.instruction_observations if item.instruction_ea is not None}
        if self.native_instruction_eas and not self.instruction_observations:
            raise ValueError("native instruction origins require ordered instruction observations")
        if self.instruction_observations and observed_eas != set(self.native_instruction_eas):
            raise ValueError("native_instruction_eas must equal resolved instruction observation EAs")
        predicate_rows = [
            (index, item) for index, item in enumerate(self.instruction_observations)
            if item.predicate_observation is not None
        ]
        if predicate_rows:
            if len(predicate_rows) != 1 or predicate_rows[0][0] != len(self.instruction_observations) - 1:
                raise ValueError("predicate observation must belong to the exact tail")
            if self.block_kind is not BlockKind.TWO_WAY or len(self.successor_serials) != 2:
                raise ValueError("predicate observation requires exactly two conditional successors")
            index, tail = predicate_rows[0]
            del index
            if (
                tail.instruction_kind
                not in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
                or tail.control_transfer_kind is not ControlTransferKind.CONDITIONAL_BRANCH
            ):
                raise ValueError("predicate observation requires a conditional transfer tail")
            predicate = tail.predicate_observation
            if (
                predicate is None
                or predicate.predicate_kind is PredicateKind.TRUTHY
            ):
                raise ValueError(
                    "predicate observation requires a structured comparison predicate",
                )
            if predicate.explicit_target_serial != self.successor_serials[1]:
                raise ValueError("predicate explicit target must equal ordered taken successor")
            if self.successor_serials[0] == self.successor_serials[1]:
                raise ValueError("conditional successors must have distinct arms")
        if self.transfer_ea is not None:
            transfer_rows = [
                item for item in self.instruction_observations
                if item.instruction_ea == self.transfer_ea
            ]
            if len(transfer_rows) != 1 or transfer_rows[0].ordinal != len(self.instruction_observations) - 1:
                raise ValueError("transfer_ea must identify the tail instruction")
            if transfer_rows[0].control_transfer_kind is None:
                raise ValueError("transfer_ea must identify a control-transfer instruction")
        if self.instruction_observations:
            tail = self.instruction_observations[-1]
            if tail.control_transfer_kind is not None:
                if tail.instruction_ea is not None and self.transfer_ea != tail.instruction_ea:
                    raise ValueError("tail control transfer requires its transfer EA")
        resolve_inventory_block_sites(
            serial=self.serial,
            owner_ref=self.block_ref,
            owner_anchor_ea=self.anchor_ea if self.anchor_ea is not None else 0,
            block_kind=self.block_kind,
            successor_serials=self.successor_serials,
            instruction_observations=self.instruction_observations,
        )


@dataclass(frozen=True, slots=True)
class InventoryEffectSite:
    owner_serial: int
    owner_ref: CfgBlockRef | None
    owner_anchor_ea: int
    instruction_ordinal: int
    instruction_ea: int
    effect_kind: EffectSiteKind
    opcode: int
    width: int

    def __post_init__(self) -> None:
        _inventory_nonnegative(self.owner_serial, "owner_serial")
        if self.owner_ref is not None:
            _cfg_ref(self.owner_ref, "owner_ref")
        _inventory_ea(self.owner_anchor_ea, "owner_anchor_ea")
        _inventory_nonnegative(self.instruction_ordinal, "instruction_ordinal")
        _inventory_ea(self.instruction_ea, "instruction_ea")
        if type(self.effect_kind) is not EffectSiteKind:
            raise TypeError("effect_kind must be EffectSiteKind")
        if type(self.opcode) is not int:
            raise TypeError("opcode must be an exact int")
        _inventory_nonnegative(self.width, "width")


@dataclass(frozen=True, slots=True)
class InventoryTerminalSite:
    owner_serial: int
    owner_ref: CfgBlockRef | None
    owner_anchor_ea: int
    instruction_ordinal: int | None
    instruction_ea: int
    terminal_kind: TerminalKind

    def __post_init__(self) -> None:
        _inventory_nonnegative(self.owner_serial, "owner_serial")
        if self.owner_ref is not None:
            _cfg_ref(self.owner_ref, "owner_ref")
        _inventory_ea(self.owner_anchor_ea, "owner_anchor_ea")
        if type(self.terminal_kind) is not TerminalKind:
            raise TypeError("terminal_kind must be TerminalKind")
        if self.instruction_ordinal is None:
            if self.terminal_kind is not TerminalKind.STOP:
                raise ValueError("only synthesized STOP terminals may omit ordinal")
        else:
            _inventory_nonnegative(self.instruction_ordinal, "instruction_ordinal")
            if self.terminal_kind is TerminalKind.STOP:
                raise ValueError("STOP terminals must be synthesized")
        _inventory_ea(self.instruction_ea, "instruction_ea")


def resolve_inventory_site_binding(
    subject: SemanticSubjectRef,
    base_binding: PhaseSubjectBinding,
    *,
    effects: tuple[InventoryEffectSite, ...],
    terminals: tuple[InventoryTerminalSite, ...],
    reachable_serials: tuple[int, ...],
    serial_by_ref: dict[CfgBlockRef, int],
) -> PhaseSubjectBinding:
    """Replay one exact effect/terminal binding from closed inventory rows.

    This pure model operation is deliberately independent of the binding
    facade.  It is used both when candidate bindings are created and when an
    inventory is revalidated, so a forged binding cannot make the inventory
    self-consistent merely by changing its digest.
    """
    if type(subject) is not SemanticSubjectRef:
        raise TypeError("site subject must be SemanticSubjectRef")
    subject.__post_init__()
    if type(base_binding) is not PhaseSubjectBinding:
        raise TypeError("base_binding must be PhaseSubjectBinding")
    base_binding.__post_init__()
    if base_binding.subject != subject:
        raise ValueError("base binding subject does not match site subject")
    if type(effects) is not tuple:
        raise TypeError("effects must be an exact tuple")
    if type(terminals) is not tuple:
        raise TypeError("terminals must be an exact tuple")
    if any(type(row) is not InventoryEffectSite for row in effects):
        raise TypeError("effects must contain exact InventoryEffectSite rows")
    if any(type(row) is not InventoryTerminalSite for row in terminals):
        raise TypeError("terminals must contain exact InventoryTerminalSite rows")
    if type(reachable_serials) is not tuple:
        raise TypeError("reachable_serials must be an exact tuple")
    if reachable_serials != tuple(sorted(set(reachable_serials))):
        raise ValueError("reachable_serials must be sorted and unique")
    if any(type(serial) is not int or serial < 0 for serial in reachable_serials):
        raise TypeError("reachable_serials must contain exact non-negative ints")
    if type(serial_by_ref) is not dict:
        raise TypeError("serial_by_ref must be an exact dict")
    if any(
        type(ref) not in _CFG_REF_TYPES
        or type(serial) is not int
        or serial < 0
        for ref, serial in serial_by_ref.items()
    ):
        raise ValueError("serial_by_ref contains a non-canonical row")
    if len(set(serial_by_ref.values())) != len(serial_by_ref):
        raise ValueError("serial_by_ref serials must be unique")
    for row in (*effects, *terminals):
        row.__post_init__()
        if row.owner_serial not in reachable_serials:
            raise ValueError("inventory site row is outside reachable_serials")
        if row.owner_ref is not None:
            owner_serial = serial_by_ref.get(row.owner_ref)
            if owner_serial is None:
                raise ValueError("inventory site owner is foreign to serial_by_ref")
            if row.owner_serial != owner_serial:
                raise ValueError("inventory site owner serial disagrees with serial_by_ref")
    if subject.role is SemanticSubjectRole.EFFECT_SITE:
        if type(subject.locator) is not EffectSubjectLocator:
            raise TypeError("effect site subject requires EffectSubjectLocator")
        locator = subject.locator
        matches = tuple(
            row for row in effects
            if row.owner_ref == locator.owner_ref
            and row.owner_anchor_ea == locator.owner_anchor_ea
            and row.instruction_ea == locator.instruction_ea
            and row.effect_kind is locator.effect_kind
            and row.owner_serial in reachable_serials
        )
        owner_ref = locator.owner_ref
        owner_serial = serial_by_ref.get(owner_ref)
        owner_present = (
            owner_serial is not None
            and base_binding.status is SubjectBindingStatus.UNIQUE
            and base_binding.block_ref == owner_ref
            and base_binding.serial == owner_serial
            and base_binding.anchor_ea == locator.owner_anchor_ea
            and locator.instruction_ea in base_binding.native_instruction_eas
        )
    elif subject.role is SemanticSubjectRole.TERMINAL_SITE:
        if type(subject.locator) is not TerminalSubjectLocator:
            raise TypeError("terminal site subject requires TerminalSubjectLocator")
        locator = subject.locator
        matches = tuple(
            row for row in terminals
            if row.owner_ref == locator.block_ref
            and row.owner_anchor_ea == locator.anchor_ea
            and row.instruction_ea == locator.instruction_ea
            and row.terminal_kind is locator.terminal_kind
            and row.owner_serial in reachable_serials
        )
        owner_ref = locator.block_ref
        owner_serial = serial_by_ref.get(owner_ref)
        owner_present = (
            owner_serial is not None
            and base_binding.status is SubjectBindingStatus.UNIQUE
            and base_binding.block_ref == owner_ref
            and base_binding.serial == owner_serial
            and base_binding.anchor_ea == locator.anchor_ea
            and locator.instruction_ea in base_binding.native_instruction_eas
        )
    else:
        raise ValueError("site resolver requires EFFECT_SITE or TERMINAL_SITE")
    if len(matches) > 1:
        raise ValueError("inventory site locator is ambiguous")
    if matches:
        if not owner_present:
            raise ValueError("site binding owner does not match present inventory site")
        return base_binding
    return PhaseSubjectBinding(
        subject=subject,
        phase=base_binding.phase,
        block_ref=None,
        graph_fingerprint=base_binding.graph_fingerprint,
        generation=base_binding.generation,
        status=SubjectBindingStatus.MISSING,
        serial=None,
        anchor_ea=None,
        native_instruction_eas=(),
        role=subject.role,
    )


@dataclass(frozen=True, slots=True)
class InventoryTopologyIncidence:
    kind: TopologyIncidenceKind
    owner_serial: int
    peer_serial: int
    source_transfer_ea: int | None

    def __post_init__(self) -> None:
        if type(self.kind) is not TopologyIncidenceKind:
            raise TypeError("kind must be TopologyIncidenceKind")
        _inventory_nonnegative(self.owner_serial, "owner_serial")
        _inventory_nonnegative(self.peer_serial, "peer_serial")
        if self.source_transfer_ea is not None:
            _inventory_ea(self.source_transfer_ea, "source_transfer_ea")


@dataclass(frozen=True, slots=True)
class TopologyEdgeRelation:
    """One directed, native-anchored edge in a prepared topology witness."""

    role: SemanticEdgeRole
    source_subject_id: str
    target_subject_id: str
    native_edge_anchor_ea: int

    def __post_init__(self) -> None:
        _enum(self.role, SemanticEdgeRole, "role")
        _id(self.source_subject_id, "source_subject_id")
        _id(self.target_subject_id, "target_subject_id")
        _ea(self.native_edge_anchor_ea, "native_edge_anchor_ea")

    @property
    def edge_role(self) -> SemanticEdgeRole:
        """Compatibility accessor for the canonical ``role`` field."""

        return self.role


@dataclass(frozen=True, slots=True)
class TopologyEvidencePayload:
    subject_id: str
    predecessor_subject_ids: tuple[str, ...]
    successor_subject_ids: tuple[str, ...]
    reciprocal_edges: bool
    expected_shape_digest: str
    candidate_shape_digest: str
    expected_edge_relations: tuple[TopologyEdgeRelation, ...] = ()
    candidate_edge_relations: tuple[TopologyEdgeRelation, ...] = ()

    def __post_init__(self) -> None:
        _id(self.subject_id, "subject_id")
        for name in ("predecessor_subject_ids", "successor_subject_ids"):
            values = _tuple(getattr(self, name), name, sort=True)
            for value in values:
                _id(value, f"{name} item")
            object.__setattr__(self, name, values)
        if not isinstance(self.reciprocal_edges, bool):
            raise TypeError("reciprocal_edges must be a bool")
        _id(self.expected_shape_digest, "expected_shape_digest")
        _id(self.candidate_shape_digest, "candidate_shape_digest")
        for name in ("expected_edge_relations", "candidate_edge_relations"):
            relations = _tuple(getattr(self, name), name, sort=True)
            if any(type(value) is not TopologyEdgeRelation for value in relations):
                raise TypeError(f"{name} must contain TopologyEdgeRelation values")
            object.__setattr__(self, name, relations)
        if self.expected_edge_relations or self.candidate_edge_relations:
            if self.expected_shape_digest != authority_id(self.expected_edge_relations):
                raise ValueError("expected topology digest does not match edge relations")
            if self.candidate_shape_digest != authority_id(self.candidate_edge_relations):
                raise ValueError("candidate topology digest does not match edge relations")


@dataclass(frozen=True, slots=True)
class StructuralLineageEvidencePayload:
    source_subject_id: str
    candidate_subject_ids: tuple[str, ...]
    disposition: StructuralDisposition
    reciprocal_native_origin_eas: tuple[int, ...]
    claim_id: str | None
    source_subject_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.source_subject_id, "source_subject_id")
        candidates = _tuple(self.candidate_subject_ids, "candidate_subject_ids", sort=True)
        for value in candidates:
            _id(value, "candidate_subject_ids item")
        object.__setattr__(self, "candidate_subject_ids", candidates)
        _enum(self.disposition, StructuralDisposition, "disposition")
        eas = _tuple(self.reciprocal_native_origin_eas, "reciprocal_native_origin_eas", sort=True)
        for ea in eas:
            _ea(ea, "reciprocal_native_origin_eas item")
        object.__setattr__(self, "reciprocal_native_origin_eas", eas)
        if self.claim_id is not None:
            _id(self.claim_id, "claim_id")
        sources = _tuple(self.source_subject_ids, "source_subject_ids", sort=True)
        for value in sources:
            _id(value, "source_subject_ids item")
        if sources and self.source_subject_id not in sources:
            raise ValueError("lineage source group must include source_subject_id")
        normalized_sources = sources or (self.source_subject_id,)
        if self.disposition is StructuralDisposition.FOLDED and (
            len(normalized_sources) < 2 or len(candidates) != 1
        ):
            raise ValueError("folded lineage requires multiple sources and one candidate")
        if self.disposition in (StructuralDisposition.PRESERVED, StructuralDisposition.SPLIT) and len(normalized_sources) != 1:
            raise ValueError("preserved and split lineage require one source group")
        object.__setattr__(self, "source_subject_ids", normalized_sources)


@dataclass(frozen=True, slots=True)
class SemanticRouteEvidencePayload:
    route_subject_id: str
    proof_ids: tuple[str, ...]
    atomic_group_id: str
    source_subject_id: str
    destination_subject_ids: tuple[str, ...]
    matched: bool
    dag_endpoint_subject_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("route_subject_id", "atomic_group_id", "source_subject_id"):
            _id(getattr(self, name), name)
        for name in ("proof_ids", "destination_subject_ids", "dag_endpoint_subject_ids"):
            # Proof IDs are an unordered scope. Destination IDs are not:
            # they are the projection of RouteSubjectLocator's canonical
            # (ref, EA) pairs and must retain that paired order.
            values = _tuple(getattr(self, name), name, sort=name == "proof_ids")
            for value in values:
                _id(value, f"{name} item")
            object.__setattr__(self, name, values)
        if not isinstance(self.matched, bool):
            raise TypeError("matched must be a bool")


@dataclass(frozen=True, slots=True)
class EffectSiteEvidencePayload:
    effect_subject_id: str
    effect_kind: EffectSiteKind
    instruction_ea: int
    opcode: int
    width: int | None
    storage_identity: StorageIdentity | None
    normalized_state: int | None
    provider_mode: ProviderConsensusMode
    provider_ids: tuple[str, ...]
    preserved: bool

    def __post_init__(self) -> None:
        _id(self.effect_subject_id, "effect_subject_id")
        _enum(self.effect_kind, EffectSiteKind, "effect_kind")
        object.__setattr__(self, "instruction_ea", _ea(self.instruction_ea, "instruction_ea"))
        _nonnegative(self.opcode, "opcode")
        if self.width is not None and self.width <= 0:
            raise ValueError("width must be positive")
        if self.width is not None:
            _nonnegative(self.width, "width")
        if self.storage_identity is not None and type(self.storage_identity) is not StorageIdentity:
            raise TypeError("storage_identity must be a StorageIdentity or None")
        if self.normalized_state is not None:
            _nonnegative(self.normalized_state, "normalized_state")
        _enum(self.provider_mode, ProviderConsensusMode, "provider_mode")
        providers = _tuple(self.provider_ids, "provider_ids", sort=True)
        for provider in providers:
            _id(provider, "provider_ids item")
        if self.provider_mode is ProviderConsensusMode.NOT_APPLICABLE and providers:
            raise ValueError("not-applicable provider mode requires no providers")
        if self.provider_mode is ProviderConsensusMode.SINGLE_PROVIDER and len(providers) != 1:
            raise ValueError("single-provider mode requires exactly one provider")
        if self.provider_mode is ProviderConsensusMode.MULTI_PROVIDER_CONSENSUS and len(providers) < 2:
            raise ValueError("multi-provider mode requires at least two providers")
        object.__setattr__(self, "provider_ids", providers)
        if not isinstance(self.preserved, bool):
            raise TypeError("preserved must be a bool")


@dataclass(frozen=True, slots=True)
class ReachabilityEvidencePayload:
    root_subject_id: str
    target_subject_id: str
    reachable: bool
    path_subject_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.root_subject_id, "root_subject_id")
        _id(self.target_subject_id, "target_subject_id")
        if not isinstance(self.reachable, bool):
            raise TypeError("reachable must be a bool")
        path = _tuple(self.path_subject_ids, "path_subject_ids")
        for value in path:
            _id(value, "path_subject_ids item")
        object.__setattr__(self, "path_subject_ids", path)


@dataclass(frozen=True, slots=True)
class UseDefAuditEvidencePayload:
    fragment_id: str
    state_identity: StorageIdentity
    executed: bool
    fragment_atomic: bool
    actionable_non_state_severance_count: int
    violation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.fragment_id, "fragment_id")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be a StorageIdentity")
        if not isinstance(self.executed, bool) or not isinstance(self.fragment_atomic, bool):
            raise TypeError("executed and fragment_atomic must be bools")
        _nonnegative(self.actionable_non_state_severance_count, "actionable_non_state_severance_count")
        violations = _tuple(self.violation_ids, "violation_ids", sort=True)
        for value in violations:
            _id(value, "violation_ids item")
        object.__setattr__(self, "violation_ids", violations)
        if self.executed and self.fragment_atomic and len(violations) != self.actionable_non_state_severance_count:
            raise ValueError("executed atomic use-def audit count must equal violation IDs")


@dataclass(frozen=True, slots=True)
class CorridorCoverageEvidencePayload:
    corridor_subject_id: str
    forecast_id: str
    phase_result_id: str
    covered_path_ids: tuple[str, ...]
    residual_path_ids: tuple[str, ...]
    drifted_path_ids: tuple[str, ...]
    enumeration_complete: bool
    matched_semantic_exclusion_ids: tuple[str, ...]
    source_dispatcher_reachable: bool = False
    candidate_dispatcher_reachable: bool = False

    def __post_init__(self) -> None:
        _id(self.corridor_subject_id, "corridor_subject_id")
        _id(self.forecast_id, "forecast_id")
        _id(self.phase_result_id, "phase_result_id")
        for name in ("covered_path_ids", "residual_path_ids", "drifted_path_ids"):
            object.__setattr__(self, name, _strict_id_tuple(getattr(self, name), name))
        if set(self.covered_path_ids) & set(self.residual_path_ids) or set(self.drifted_path_ids) & (set(self.covered_path_ids) | set(self.residual_path_ids)):
            raise ValueError("corridor evidence path partitions overlap")
        if type(self.enumeration_complete) is not bool:
            raise TypeError("enumeration_complete must be an exact bool")
        if type(self.source_dispatcher_reachable) is not bool or type(self.candidate_dispatcher_reachable) is not bool:
            raise TypeError("dispatcher reachability flags must be exact bools")
        object.__setattr__(self, "matched_semantic_exclusion_ids", _strict_id_tuple(
            self.matched_semantic_exclusion_ids, "matched_semantic_exclusion_ids"
        ))


@dataclass(frozen=True, slots=True)
class PatchStepEvidencePayload:
    plan_id: str
    step_index: int
    step_type: str
    owner_ref: CfgBlockRef
    step_digest: str
    host_ea: int | None
    host_opcode: int | None
    value_size: int | None
    creation_spec_digest: str | None = None

    def __post_init__(self) -> None:
        _id(self.plan_id, "plan_id")
        _nonnegative(self.step_index, "step_index")
        _text(self.step_type, "step_type")
        _cfg_ref(self.owner_ref, "owner_ref")
        _id(self.step_digest, "step_digest")
        for name in ("host_ea",):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _ea(value, name))
        for name in ("host_opcode", "value_size"):
            value = getattr(self, name)
            if value is not None:
                _nonnegative(value, name)
        if self.creation_spec_digest is not None:
            _id(self.creation_spec_digest, "creation_spec_digest")


@dataclass(frozen=True, slots=True)
class GenericCfgGateEvidencePayload:
    gate: GenericCfgGateKind
    passed: bool
    affected_subject_ids: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        _enum(self.gate, GenericCfgGateKind, "gate")
        if not isinstance(self.passed, bool):
            raise TypeError("passed must be a bool")
        values = _tuple(self.affected_subject_ids, "affected_subject_ids", sort=True)
        for value in values:
            _id(value, "affected_subject_ids item")
        object.__setattr__(self, "affected_subject_ids", values)
        _text(self.reason_code, "reason_code")


AuthorityEvidencePayload: TypeAlias = (
    PhaseBindingEvidencePayload | TopologyEvidencePayload
    | StructuralLineageEvidencePayload | SemanticRouteEvidencePayload
    | EffectSiteEvidencePayload | ReachabilityEvidencePayload
    | UseDefAuditEvidencePayload | CorridorCoverageEvidencePayload
    | TerminalCycleEvidencePayload | DetachedComponentEvidencePayload
    | PatchStepEvidencePayload | GenericCfgGateEvidencePayload
)

_PAYLOAD_BY_KIND = {
    AuthorityEvidenceKind.PHASE_BINDING: PhaseBindingEvidencePayload,
    AuthorityEvidenceKind.TOPOLOGY: TopologyEvidencePayload,
    AuthorityEvidenceKind.STRUCTURAL_LINEAGE: StructuralLineageEvidencePayload,
    AuthorityEvidenceKind.SEMANTIC_ROUTE: SemanticRouteEvidencePayload,
    AuthorityEvidenceKind.EFFECT_SITE: EffectSiteEvidencePayload,
    AuthorityEvidenceKind.REACHABILITY: ReachabilityEvidencePayload,
    AuthorityEvidenceKind.USE_DEF_AUDIT: UseDefAuditEvidencePayload,
    AuthorityEvidenceKind.CORRIDOR_COVERAGE: CorridorCoverageEvidencePayload,
    AuthorityEvidenceKind.TERMINAL_CYCLE: TerminalCycleEvidencePayload,
    AuthorityEvidenceKind.DETACHED_COMPONENT: DetachedComponentEvidencePayload,
    AuthorityEvidenceKind.PATCH_STEP: PatchStepEvidencePayload,
    AuthorityEvidenceKind.GENERIC_CFG_GATE: GenericCfgGateEvidencePayload,
}


@dataclass(frozen=True, slots=True)
class AuthorityEvidence:
    evidence_id: str
    kind: AuthorityEvidenceKind
    subject: SemanticSubjectRef
    phase: UnflattenAuthorityPhase
    payload: AuthorityEvidencePayload

    def __post_init__(self) -> None:
        _id(self.evidence_id, "evidence_id")
        _enum(self.kind, AuthorityEvidenceKind, "kind")
        if type(self.subject) is not SemanticSubjectRef:
            raise TypeError("subject must be a SemanticSubjectRef")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        expected = _PAYLOAD_BY_KIND[self.kind]
        if type(self.payload) is not expected:
            raise TypeError("evidence payload type does not match evidence kind")
        if self.evidence_id != evidence_id(self):
            raise ValueError("evidence_id does not match canonical evidence content")


@dataclass(frozen=True, slots=True)
class GenericCfgGateResult:
    gate: GenericCfgGateKind
    passed: bool
    supported_subject_ids: tuple[str, ...]
    refuted_subject_ids: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        _enum(self.gate, GenericCfgGateKind, "gate")
        if not isinstance(self.passed, bool):
            raise TypeError("passed must be a bool")
        for name in ("supported_subject_ids", "refuted_subject_ids"):
            values = _tuple(getattr(self, name), name, sort=True)
            for value in values:
                _id(value, f"{name} item")
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must not contain duplicate subject IDs")
            object.__setattr__(self, name, values)
        if set(self.supported_subject_ids) & set(self.refuted_subject_ids):
            raise ValueError("generic gate support and refutation must be disjoint")
        if self.passed != (not self.refuted_subject_ids):
            raise ValueError("generic gate passed must equal not refuted")
        _text(self.reason_code, "reason_code")


@dataclass(frozen=True, slots=True)
class ProviderConsensusWitness:
    mode: ProviderConsensusMode
    provider_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _enum(self.mode, ProviderConsensusMode, "mode")
        providers = _tuple(self.provider_ids, "provider_ids", sort=True)
        for provider in providers:
            _id(provider, "provider_ids item")
        if self.mode is ProviderConsensusMode.NOT_APPLICABLE and providers:
            raise ValueError("not-applicable provider mode requires no providers")
        if self.mode is ProviderConsensusMode.SINGLE_PROVIDER and len(providers) != 1:
            raise ValueError("single-provider mode requires exactly one provider")
        if self.mode is ProviderConsensusMode.MULTI_PROVIDER_CONSENSUS and len(providers) < 2:
            raise ValueError("multi-provider mode requires at least two providers")
        object.__setattr__(self, "provider_ids", providers)


def _claim_subject(value: object, kind: SemanticSubjectKind, role: SemanticSubjectRole, locator: type | tuple[type, ...], label: str) -> None:
    if type(value) is not SemanticSubjectRef:
        raise TypeError(f"{label} must be a SemanticSubjectRef")
    locators = locator if type(locator) is tuple else (locator,)
    if value.kind is not kind or value.role is not role or type(value.locator) not in locators:
        raise ValueError(f"{label} has an unsupported subject kind/role/locator")


def _subject_block_pair(subject: SemanticSubjectRef) -> tuple[CfgBlockRef, int]:
    if type(subject.locator) is not BlockSubjectLocator:
        raise ValueError("claim subject must be block-backed")
    return subject.locator.block_ref, subject.locator.anchor_ea


def _route_pairs(subject: SemanticSubjectRef) -> tuple[tuple[CfgBlockRef, int], ...]:
    if type(subject.locator) is not RouteSubjectLocator:
        raise ValueError("claim route subject must use RouteSubjectLocator")
    locator = subject.locator
    return (
        (locator.source_ref, locator.source_anchor_ea),
        *tuple(
            (item.block_ref, item.anchor_ea)
            for item in locator.native_destination_members()
            if type(item) is BlockSubjectLocator
        ),
    )


def _route_destination_locator(subject: SemanticSubjectRef) -> BlockSubjectLocator | LogicalFunctionExitSubjectLocator:
    """Return the typed native/logical destination locator owned by one subject."""
    if type(subject.locator) not in (
        BlockSubjectLocator, LogicalFunctionExitSubjectLocator,
    ):
        raise ValueError("route destination subject must use a typed destination locator")
    return subject.locator


def _claim_subjects(claim: ProducerUnflattenClaim) -> tuple[SemanticSubjectRef, ...]:
    subjects: list[SemanticSubjectRef] = []
    for field in fields(claim):
        value = getattr(claim, field.name)
        if type(value) is SemanticSubjectRef:
            subjects.append(value)
        elif isinstance(value, tuple):
            subjects.extend(item for item in value if type(item) is SemanticSubjectRef)
    return tuple(subjects)


def _subject_refs(subject: SemanticSubjectRef) -> tuple[CfgBlockRef, ...]:
    locator = subject.locator
    if type(locator) is BlockSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is LogicalFunctionExitSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is EdgeSubjectLocator:
        return (locator.source_ref, locator.target_ref)
    if type(locator) is RouteSubjectLocator:
        return (
            locator.source_ref,
            *(item.block_ref for item in locator.native_destination_members()),
        )
    if type(locator) is EffectSubjectLocator:
        return (locator.owner_ref,)
    if type(locator) is HandlerSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is TerminalSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is ValueFlowSubjectLocator:
        return tuple(locator.redirect_owner_refs)
    if type(locator) is CorridorSubjectLocator:
        return (locator.entry_ref, *locator.member_refs)
    raise TypeError("unknown subject locator")


def _subject_pairs(subject: SemanticSubjectRef) -> tuple[tuple[CfgBlockRef, int | None], ...]:
    locator = subject.locator
    if type(locator) is BlockSubjectLocator:
        return ((locator.block_ref, locator.anchor_ea),)
    if type(locator) is LogicalFunctionExitSubjectLocator:
        return ((locator.block_ref, None),)
    if type(locator) is EdgeSubjectLocator:
        return (
            (locator.source_ref, locator.source_anchor_ea),
            (locator.target_ref, locator.target_anchor_ea),
        )
    if type(locator) is RouteSubjectLocator:
        return (
            (locator.source_ref, locator.source_anchor_ea),
            *tuple((item.block_ref, item.anchor_ea)
                   if type(item) is BlockSubjectLocator else (item.block_ref, None)
                   for item in locator.native_destination_members()),
        )
    if type(locator) is EffectSubjectLocator:
        return ((locator.owner_ref, locator.owner_anchor_ea),)
    if type(locator) is HandlerSubjectLocator:
        return ((locator.block_ref, locator.anchor_ea),)
    if type(locator) is TerminalSubjectLocator:
        return ((locator.block_ref, locator.anchor_ea),)
    if type(locator) is ValueFlowSubjectLocator:
        return tuple((ref, None) for ref in locator.redirect_owner_refs)
    if type(locator) is CorridorSubjectLocator:
        return (
            (locator.entry_ref, locator.entry_anchor_ea),
            *tuple(zip(locator.member_refs, locator.member_anchor_eas)),
        )
    raise TypeError("unknown subject locator")


def _claim_common(claim_id: object, kind: object, expected: UnflattenClaimKind, generation: object) -> None:
    _id(claim_id, "claim_id")
    if kind is not expected:
        raise ValueError("claim kind does not match claim type")
    _generation(generation, "source_generation")


@dataclass(frozen=True, slots=True)
class RetiredDispatcherInfrastructureClaim:
    claim_id: str
    kind: Literal[UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE]
    infrastructure_subject: SemanticSubjectRef
    corridor_subject: SemanticSubjectRef
    member_subjects: tuple[SemanticSubjectRef, ...]
    candidate_evidence_ids: tuple[str, ...]
    source_generation: int
    candidate_catalog: RetirementCandidateCatalog

    def __post_init__(self) -> None:
        _claim_common(self.claim_id, self.kind, UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE, self.source_generation)
        _claim_subject(self.infrastructure_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, BlockSubjectLocator, "infrastructure_subject")
        _claim_subject(self.corridor_subject, SemanticSubjectKind.CORRIDOR, SemanticSubjectRole.DISPATCHER_CORRIDOR, CorridorSubjectLocator, "corridor_subject")
        members = _tuple(self.member_subjects, "member_subjects", sort=True)
        for member in members:
            _claim_subject(member, SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, BlockSubjectLocator, "member_subject")
        evidence_ids = _strict_id_tuple(
            self.candidate_evidence_ids, "candidate_evidence_ids",
        )
        if not evidence_ids:
            raise ValueError("retirement claim requires candidate evidence")
        object.__setattr__(self, "member_subjects", members)
        object.__setattr__(self, "candidate_evidence_ids", evidence_ids)
        expected_members = tuple(
            zip(self.corridor_subject.locator.member_refs,
                self.corridor_subject.locator.member_anchor_eas)
        )
        actual_members = tuple(_subject_block_pair(member) for member in members)
        if type(self.candidate_catalog) is not RetirementCandidateCatalog:
            raise TypeError("candidate_catalog must be RetirementCandidateCatalog")
        if self.candidate_catalog.source_generation != self.source_generation:
            raise ValueError("retirement candidate catalog generation differs from claim")
        catalog_members = tuple(
            (member.block_ref, member.anchor_ea)
            for member in self.candidate_catalog.plan_members
        )
        if catalog_members != expected_members:
            raise ValueError("retirement candidate catalog must match exact corridor member order")
        candidate_members = tuple(
            (member.block_ref, member.anchor_ea)
            for member in self.candidate_catalog.candidates
        )
        if set(actual_members) != set(candidate_members):
            raise ValueError("retirement claim members must match candidate catalog")
        catalog_evidence_ids = tuple(sorted({
            evidence_id
            for candidate in self.candidate_catalog.candidates
            for evidence_id in candidate.evidence_ids
        }))
        if evidence_ids != catalog_evidence_ids:
            raise ValueError("retirement claim evidence IDs must match candidate catalog")
        if self.claim_id != claim_id(self):
            raise ValueError("claim_id does not match canonical claim content")


@dataclass(frozen=True, slots=True)
class DetachedDeadHandlerComponentClaim:
    """Frozen producer claim for one exact detached dead-handler component.

    The claim intentionally carries only source-catalog subjects.  Candidate
    topology, reachability, effects, and terminal equivalence are all bound
    later by the transaction authority.
    """

    claim_id: str
    kind: Literal[UnflattenClaimKind.DETACHED_DEAD_HANDLER_COMPONENT]
    dispatcher_subject: SemanticSubjectRef
    dead_handler_subjects: tuple[SemanticSubjectRef, ...]
    retained_handler_subjects: tuple[SemanticSubjectRef, ...]
    component_subjects: tuple[SemanticSubjectRef, ...]
    comparison_region_subjects: tuple[SemanticSubjectRef, ...]
    source_generation: int

    def __post_init__(self) -> None:
        _claim_common(self.claim_id, self.kind, UnflattenClaimKind.DETACHED_DEAD_HANDLER_COMPONENT, self.source_generation)
        _claim_subject(self.dispatcher_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_ENTRY, BlockSubjectLocator, "dispatcher_subject")
        dead = _tuple(self.dead_handler_subjects, "dead_handler_subjects", sort=True)
        retained = _tuple(self.retained_handler_subjects, "retained_handler_subjects", sort=True)
        component = _tuple(self.component_subjects, "component_subjects", sort=True)
        comparison = _tuple(
            self.comparison_region_subjects,
            "comparison_region_subjects",
            sort=True,
        )
        if not dead or not retained or not component or not comparison:
            raise ValueError(
                "detached component claim requires dead, retained, component, "
                "and comparison-region subjects"
            )
        for subject in (*dead, *retained):
            _claim_subject(subject, SemanticSubjectKind.HANDLER, SemanticSubjectRole.AUTHORITATIVE_HANDLER, HandlerSubjectLocator, "handler_subject")
        for subject in component:
            _claim_subject(subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.DETACHED_DEAD_HANDLER_COMPONENT, BlockSubjectLocator, "component_subject")
        for subject in comparison:
            _claim_subject(
                subject, SemanticSubjectKind.BLOCK,
                SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                BlockSubjectLocator, "comparison_region_subject",
            )
        if {subject.subject_id for subject in dead} & {subject.subject_id for subject in retained}:
            raise ValueError("dead and retained handler subjects overlap")
        if not {subject.block_ref for subject in dead} <= {subject.block_ref for subject in component}:
            raise ValueError("component subjects must contain every dead handler")
        if {subject.block_ref for subject in retained} & {
            subject.block_ref for subject in component
        }:
            raise ValueError("detached component must not contain retained handlers")
        object.__setattr__(self, "dead_handler_subjects", dead)
        object.__setattr__(self, "retained_handler_subjects", retained)
        object.__setattr__(self, "component_subjects", component)
        object.__setattr__(self, "comparison_region_subjects", comparison)
        if self.dispatcher_subject.block_ref not in {
            subject.block_ref for subject in comparison
        }:
            raise ValueError("comparison region must contain the dispatcher")
        if self.claim_id != claim_id(self):
            raise ValueError("claim_id does not match canonical claim content")


@dataclass(frozen=True, slots=True)
class EquivalentSemanticRouteClaim:
    claim_id: str
    kind: Literal[UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE]
    retired_route_subject: SemanticSubjectRef
    replacement_route_subject: SemanticSubjectRef
    source_subject: SemanticSubjectRef
    destination_subjects: tuple[SemanticSubjectRef, ...]
    route_proof_ids: tuple[str, ...]
    atomic_group_id: str
    source_generation: int
    dag_endpoint_subjects: tuple[SemanticSubjectRef, ...] = ()

    def __post_init__(self) -> None:
        _claim_common(self.claim_id, self.kind, UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE, self.source_generation)
        for name in ("retired_route_subject", "replacement_route_subject"):
            _claim_subject(getattr(self, name), SemanticSubjectKind.ROUTE, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, RouteSubjectLocator, name)
        _claim_subject(self.source_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, BlockSubjectLocator, "source_subject")
        destinations = _tuple(self.destination_subjects, "destination_subjects", sort=True)
        for subject in destinations:
            if (
                type(subject) is not SemanticSubjectRef
                or subject.kind is not SemanticSubjectKind.BLOCK
                or subject.role is not SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
                or type(subject.locator) is not BlockSubjectLocator
            ):
                raise ValueError("destination_subject has an unsupported route destination locator")
        dag_endpoints = _tuple(self.dag_endpoint_subjects, "dag_endpoint_subjects", sort=True)
        for subject in dag_endpoints:
            if (
                type(subject) is not SemanticSubjectRef
                or subject.kind is not SemanticSubjectKind.BLOCK
                or subject.role is not SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT
                or type(subject.locator) is not LogicalFunctionExitSubjectLocator
            ):
                raise ValueError("dag_endpoint_subject has an unsupported logical endpoint locator")
        proofs = _tuple(self.route_proof_ids, "route_proof_ids", sort=True)
        for proof in proofs:
            _id(proof, "route_proof_ids item")
        if len(proofs) != 1:
            raise ValueError("equivalent route claim must select exactly one proof")
        _id(self.atomic_group_id, "atomic_group_id")
        object.__setattr__(self, "destination_subjects", destinations)
        object.__setattr__(self, "dag_endpoint_subjects", dag_endpoints)
        object.__setattr__(self, "route_proof_ids", proofs)
        source_pair = _subject_block_pair(self.source_subject)
        destination_locators = tuple(
            _route_destination_locator(subject) for subject in destinations
        )
        dag_endpoint_locators = tuple(
            _route_destination_locator(subject) for subject in dag_endpoints
        )
        retired_locator = self.retired_route_subject.locator
        replacement_locator = self.replacement_route_subject.locator
        if self.retired_route_subject != self.replacement_route_subject:
            raise ValueError(
                "equivalent route claim must use one stable route subject"
            )
        if (
            (retired_locator.source_ref, retired_locator.source_anchor_ea) != source_pair
            or (replacement_locator.source_ref, replacement_locator.source_anchor_ea) != source_pair
            or set(retired_locator.native_destination_members()) != set(destination_locators)
            or set(replacement_locator.native_destination_members()) != set(destination_locators)
            or set(retired_locator.dag_endpoint_locators) != set(dag_endpoint_locators)
            or set(replacement_locator.dag_endpoint_locators) != set(dag_endpoint_locators)
        ):
            raise ValueError("route claim subjects must match route locator members")
        if (
            self.atomic_group_id != self.retired_route_subject.locator.atomic_group_id
            or self.atomic_group_id != self.replacement_route_subject.locator.atomic_group_id
            or proofs[0] != self.retired_route_subject.locator.proof_id
            or proofs[0] != self.replacement_route_subject.locator.proof_id
        ):
            raise ValueError("route claim atomic_group_id must match route locators")
        if self.claim_id != claim_id(self):
            raise ValueError("claim_id does not match canonical claim content")


@dataclass(frozen=True, slots=True)
class ExactInfeasibleEffectClaim:
    claim_id: str
    kind: Literal[UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT]
    effect_subject: SemanticSubjectRef
    source_subject: SemanticSubjectRef
    predicate_subject: SemanticSubjectRef
    selected_target_subject: SemanticSubjectRef
    discarded_effect_subject: SemanticSubjectRef
    normalized_state: int
    state_identity: StorageIdentity
    width: int
    source_write_ea: int
    predicate_branch_ea: int
    discarded_effect_ea: int
    selected_edge_role: SemanticEdgeRole
    route_proof_ids: tuple[str, ...]
    consensus: ProviderConsensusWitness
    source_generation: int

    def __post_init__(self) -> None:
        _claim_common(self.claim_id, self.kind, UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT, self.source_generation)
        for name in ("effect_subject", "discarded_effect_subject"):
            _claim_subject(getattr(self, name), SemanticSubjectKind.EFFECT, SemanticSubjectRole.EFFECT_SITE, EffectSubjectLocator, name)
        if self.effect_subject != self.discarded_effect_subject:
            raise ValueError("exact effect subject must equal discarded effect subject")
        _claim_subject(self.source_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_SOURCE, BlockSubjectLocator, "source_subject")
        _claim_subject(self.predicate_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_PREDICATE, BlockSubjectLocator, "predicate_subject")
        _claim_subject(self.selected_target_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_SELECTED_TARGET, BlockSubjectLocator, "selected_target_subject")
        _nonnegative(self.normalized_state, "normalized_state")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be a StorageIdentity")
        if self.width <= 0:
            raise ValueError("width must be positive")
        _nonnegative(self.width, "width")
        for name in ("source_write_ea", "predicate_branch_ea", "discarded_effect_ea"):
            object.__setattr__(self, name, _ea(getattr(self, name), name))
        effect_locator = self.discarded_effect_subject.locator
        if (
            effect_locator.instruction_ea != self.discarded_effect_ea
            or effect_locator.effect_kind not in {EffectSiteKind.CALL, EffectSiteKind.STORE}
        ):
            raise ValueError("exact effect locator does not match discarded effect site")
        _enum(self.selected_edge_role, SemanticEdgeRole, "selected_edge_role")
        proofs = _tuple(self.route_proof_ids, "route_proof_ids", sort=True)
        if len(proofs) != 1:
            raise ValueError("exact-effect claims require exactly one route proof")
        for proof in proofs:
            _id(proof, "route_proof_ids item")
        object.__setattr__(self, "route_proof_ids", proofs)
        if type(self.consensus) is not ProviderConsensusWitness:
            raise TypeError("consensus must be a ProviderConsensusWitness")
        if (
            self.consensus.mode is not ProviderConsensusMode.NOT_APPLICABLE
            or self.consensus.provider_ids
        ):
            raise ValueError("exact-effect claims do not admit provider consensus")
        if self.claim_id != claim_id(self):
            raise ValueError("claim_id does not match canonical claim content")


@dataclass(frozen=True, slots=True)
class LocalAliasEffectScalarizationClaim:
    claim_id: str
    kind: Literal[UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION]
    owner_subject: SemanticSubjectRef
    step_index: int
    host_ea: int
    host_opcode: int
    alias_token: str
    base_token: str
    host_text_sha1: str | None
    value_size: int | None
    step_digest: str
    source_generation: int

    def __post_init__(self) -> None:
        _claim_common(self.claim_id, self.kind, UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION, self.source_generation)
        _claim_subject(self.owner_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.EFFECT_SITE, BlockSubjectLocator, "owner_subject")
        _nonnegative(self.step_index, "step_index")
        object.__setattr__(self, "host_ea", _ea(self.host_ea, "host_ea"))
        _nonnegative(self.host_opcode, "host_opcode")
        _text(self.alias_token, "alias_token")
        _text(self.base_token, "base_token")
        if self.host_text_sha1 is not None:
            if not isinstance(self.host_text_sha1, str) or not _SHA1_RE.fullmatch(self.host_text_sha1):
                raise ValueError("host_text_sha1 must be lowercase 16-hex or None")
        if self.value_size is not None:
            _nonnegative(self.value_size, "value_size")
        _id(self.step_digest, "step_digest")
        if self.claim_id != claim_id(self):
            raise ValueError("claim_id does not match canonical claim content")


@dataclass(frozen=True, slots=True)
class TerminalCycleBreakClaim:
    claim_id: str
    kind: Literal[UnflattenClaimKind.TERMINAL_CYCLE_BREAK]
    cycle_subject: SemanticSubjectRef
    cleanup_source_subject: SemanticSubjectRef
    terminal_subject: SemanticSubjectRef
    terminal_route_proof_ids: tuple[str, ...]
    source_generation: int

    def __post_init__(self) -> None:
        _claim_common(self.claim_id, self.kind, UnflattenClaimKind.TERMINAL_CYCLE_BREAK, self.source_generation)
        _claim_subject(self.cycle_subject, SemanticSubjectKind.CORRIDOR, SemanticSubjectRole.DISPATCHER_CORRIDOR, CorridorSubjectLocator, "cycle_subject")
        _claim_subject(self.cleanup_source_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, BlockSubjectLocator, "cleanup_source_subject")
        _claim_subject(
            self.terminal_subject,
            SemanticSubjectKind.TERMINAL,
            SemanticSubjectRole.TERMINAL_SITE,
            (TerminalSubjectLocator, LogicalFunctionExitSubjectLocator),
            "terminal_subject",
        )
        proofs = _tuple(self.terminal_route_proof_ids, "terminal_route_proof_ids", sort=True)
        for proof in proofs:
            _id(proof, "terminal_route_proof_ids item")
        if len(proofs) != 1:
            raise ValueError(
                "terminal route proof selection must contain exactly one proof"
            )
        object.__setattr__(self, "terminal_route_proof_ids", proofs)
        if self.claim_id != claim_id(self):
            raise ValueError("claim_id does not match canonical claim content")


ProducerUnflattenClaim: TypeAlias = (
    RetiredDispatcherInfrastructureClaim | DetachedDeadHandlerComponentClaim | EquivalentSemanticRouteClaim
    | ExactInfeasibleEffectClaim | TerminalCycleBreakClaim
)
TransactionDerivedUnflattenClaim: TypeAlias = LocalAliasEffectScalarizationClaim
UnflattenClaim: TypeAlias = ProducerUnflattenClaim | TransactionDerivedUnflattenClaim


@dataclass(frozen=True, slots=True)
class EntryEndpointLivenessForecast:
    """Closed producer forecast for one live-safe entry redirect.

    The redirect owner and physical state writer are deliberately distinct
    coordinates.  The producer has already selected ``route_proof_id``; later
    layers validate that exact selection rather than searching route evidence.
    """

    reason: EntryEndpointLivenessReason
    normalized_state: int
    route_proof_id: str
    redirect_owner_ref: CfgBlockRef
    state_write_source_ref: CfgBlockRef
    state_write_instruction_ea: int
    dispatcher_ref: CfgBlockRef
    replacement_ref: CfgBlockRef
    exit_path_refs: tuple[CfgBlockRef, ...]
    delivery_path_refs: tuple[CfgBlockRef, ...] = ()
    delivery_path_edges: tuple[tuple[int, int], ...] = ()
    cut_exit_path_uses: bool = False

    def __post_init__(self) -> None:
        _enum(self.reason, EntryEndpointLivenessReason, "reason")
        _nonnegative(self.normalized_state, "normalized_state")
        _id(self.route_proof_id, "route_proof_id")
        for name in (
            "redirect_owner_ref", "state_write_source_ref", "dispatcher_ref",
            "replacement_ref",
        ):
            _cfg_ref(getattr(self, name), name)
        if type(self.state_write_source_ref) is not NativeBlockRef:
            raise TypeError("entry liveness state write source must be native")
        _ea(self.state_write_instruction_ea, "state_write_instruction_ea")
        if not self.state_write_source_ref.identity.native_ranges.contains(
            self.state_write_instruction_ea
        ):
            raise ValueError("entry liveness write EA is outside source identity")
        exits = _canonical_cfg_ref_tuple(self.exit_path_refs, "exit_path_refs")
        if not exits or self.dispatcher_ref not in exits:
            raise ValueError("entry liveness forecast exit path must include dispatcher")
        if self.dispatcher_ref == self.replacement_ref:
            raise ValueError("entry liveness forecast must replace dispatcher")
        if type(self.cut_exit_path_uses) is not bool:
            raise TypeError("cut_exit_path_uses must be bool")
        object.__setattr__(self, "exit_path_refs", exits)
        # A delivery corridor is ordered evidence, unlike a block set.  Do not
        # canonical-sort it: doing so destroys the W -> ... -> D relation the
        # transaction must later rebind.
        path = tuple(self.delivery_path_refs)
        if len(set(path)) != len(path):
            raise ValueError("entry liveness forecast corridor must not repeat refs")
        for ref in path:
            _cfg_ref(ref, "delivery_path_refs item")
        if self.redirect_owner_ref != self.state_write_source_ref and not path:
            raise ValueError(
                "entry liveness distinct owner requires a delivery corridor"
            )
        if path and (path[0] != self.state_write_source_ref or path[-1] != self.dispatcher_ref):
            raise ValueError("entry liveness forecast requires exact write-to-dispatcher corridor")
        if path and self.redirect_owner_ref not in path:
            raise ValueError("entry liveness forecast owner must lie on corridor")
        if path and (len(path) < 2 or path[-2] != self.redirect_owner_ref):
            raise ValueError(
                "entry liveness forecast corridor must end at redirect owner"
            )
        if path and tuple(self.delivery_path_edges) != tuple((index, index + 1) for index in range(len(path) - 1)):
            raise ValueError("entry liveness forecast corridor edges must be exact adjacent indices")
        object.__setattr__(self, "delivery_path_refs", path)


@dataclass(frozen=True, slots=True)
class EntryEndpointLivenessAllowance:
    """Planner-sealed no-provider entry shortcut, separate from route claims.

    This deliberately carries the exact redirect coordinate rather than
    manufacturing semantic-route evidence for an endpoint shortcut.
    """

    allowance_id: str
    reason: EntryEndpointLivenessReason
    normalized_state: int
    route_proof_id: str
    entry_predecessor_owner_refs: tuple[CfgBlockRef, ...]
    dispatcher_old_target_ref: CfgBlockRef
    replacement_endpoint_ref: CfgBlockRef
    exit_path_refs: tuple[CfgBlockRef, ...]
    patch_step_index: int
    patch_step_digest: str
    state_write_source_ref: CfgBlockRef
    state_write_instruction_ea: int
    delivery_path_refs: tuple[CfgBlockRef, ...] = ()
    delivery_path_edges: tuple[tuple[int, int], ...] = ()
    cut_exit_path_uses: bool = False

    def __post_init__(self) -> None:
        # Compatibility for pre-corridor positional construction: its final
        # bool occupied the slot now used by ``delivery_path_refs``.
        legacy_positional = (
            type(self.delivery_path_refs) is bool
            and self.delivery_path_edges == ()
            and self.cut_exit_path_uses is False
        )
        if legacy_positional:
            legacy_cut_exit_path_uses = bool(self.delivery_path_refs)
            object.__setattr__(self, "delivery_path_refs", ())
            object.__setattr__(self, "cut_exit_path_uses", legacy_cut_exit_path_uses)
        _id(self.allowance_id, "allowance_id")
        _enum(self.reason, EntryEndpointLivenessReason, "reason")
        _nonnegative(self.normalized_state, "normalized_state")
        _id(self.route_proof_id, "route_proof_id")
        owners = _canonical_cfg_ref_tuple(
            self.entry_predecessor_owner_refs, "entry_predecessor_owner_refs",
        )
        if not owners:
            raise ValueError("entry liveness allowance requires entry predecessor owners")
        if len(owners) != 1:
            raise ValueError("entry liveness allowance requires exactly one entry predecessor owner")
        _cfg_ref(self.dispatcher_old_target_ref, "dispatcher_old_target_ref")
        _cfg_ref(self.replacement_endpoint_ref, "replacement_endpoint_ref")
        _cfg_ref(self.state_write_source_ref, "state_write_source_ref")
        if type(self.state_write_source_ref) is not NativeBlockRef:
            raise TypeError("entry liveness allowance state write source must be native")
        _ea(self.state_write_instruction_ea, "state_write_instruction_ea")
        if not self.state_write_source_ref.identity.native_ranges.contains(
            self.state_write_instruction_ea
        ):
            raise ValueError("entry liveness allowance write EA is outside source identity")
        if self.dispatcher_old_target_ref == self.replacement_endpoint_ref:
            raise ValueError("entry liveness allowance must replace the dispatcher target")
        exits = _canonical_cfg_ref_tuple(self.exit_path_refs, "exit_path_refs")
        if not exits or self.dispatcher_old_target_ref not in exits:
            raise ValueError("entry liveness allowance exit path must include dispatcher target")
        _nonnegative(self.patch_step_index, "patch_step_index")
        _id(self.patch_step_digest, "patch_step_digest")
        if type(self.cut_exit_path_uses) is not bool:
            raise TypeError("cut_exit_path_uses must be bool")
        expected = authority_id((
            "unflatten.entry-endpoint-liveness-allowance.v1",
            self.reason, self.normalized_state, self.route_proof_id,
            self.entry_predecessor_owner_refs, self.dispatcher_old_target_ref,
            self.replacement_endpoint_ref, self.exit_path_refs,
            self.patch_step_index, self.patch_step_digest,
            self.state_write_source_ref, self.state_write_instruction_ea,
            *((self.cut_exit_path_uses,) if legacy_positional else (
                self.delivery_path_refs, self.delivery_path_edges,
                self.cut_exit_path_uses,
            )),
        ))
        # Existing sealed receipts without a delivery corridor retain their
        # v1 identity.  A non-empty corridor is always covered by the new
        # identity form below.
        legacy_empty_expected = authority_id((
            "unflatten.entry-endpoint-liveness-allowance.v1",
            self.reason, self.normalized_state, self.route_proof_id,
            self.entry_predecessor_owner_refs, self.dispatcher_old_target_ref,
            self.replacement_endpoint_ref, self.exit_path_refs,
            self.patch_step_index, self.patch_step_digest,
            self.state_write_source_ref, self.state_write_instruction_ea,
            self.cut_exit_path_uses,
        ))
        if self.allowance_id != expected and not (
            not self.delivery_path_refs
            and not self.delivery_path_edges
            and self.allowance_id == legacy_empty_expected
        ):
            raise ValueError("entry liveness allowance ID does not match content")
        object.__setattr__(self, "entry_predecessor_owner_refs", owners)
        object.__setattr__(self, "exit_path_refs", exits)
        # Preserve producer corridor order for the same reason as the forecast.
        path = tuple(self.delivery_path_refs)
        if len(set(path)) != len(path):
            raise ValueError("entry liveness allowance corridor must not repeat refs")
        for ref in path:
            _cfg_ref(ref, "delivery_path_refs item")
        if owners[0] != self.state_write_source_ref and not path:
            raise ValueError(
                "entry liveness distinct owner requires a delivery corridor"
            )
        if path and (path[0] != self.state_write_source_ref or path[-1] != self.dispatcher_old_target_ref):
            raise ValueError("entry liveness allowance requires exact write-to-dispatcher corridor")
        if path and (owners[0] not in path or tuple(self.delivery_path_edges) != tuple((i, i + 1) for i in range(len(path) - 1))):
            raise ValueError("entry liveness allowance corridor is invalid")
        if path and (len(path) < 2 or path[-2] != owners[0]):
            raise ValueError(
                "entry liveness allowance corridor must end at redirect owner"
            )
        object.__setattr__(self, "delivery_path_refs", path)


@dataclass(frozen=True, slots=True)
class BoundEntryEndpointLivenessAllowance:
    """Transaction-minted binding for one sealed entry liveness allowance."""

    binding_id: str
    allowance: EntryEndpointLivenessAllowance
    route_proof_id: str
    patch_step_fact: PatchStepEvidencePayload
    source_fingerprint: str
    projected_fingerprint: str
    source_generation: int
    projected_generation: int
    source_inventory_digest: str
    projected_inventory_digest: str
    source_owner_successors: tuple[CfgBlockRef, ...]
    projected_owner_successors: tuple[CfgBlockRef, ...]
    source_liveness_safe: bool
    projected_redirect_realized: bool

    def __post_init__(self) -> None:
        _id(self.binding_id, "binding_id")
        if type(self.allowance) is not EntryEndpointLivenessAllowance:
            raise TypeError("allowance must be EntryEndpointLivenessAllowance")
        _id(self.route_proof_id, "route_proof_id")
        if self.route_proof_id != self.allowance.route_proof_id:
            raise ValueError("entry liveness receipt route proof differs from allowance")
        if type(self.patch_step_fact) is not PatchStepEvidencePayload:
            raise TypeError("patch_step_fact must be PatchStepEvidencePayload")
        for name in (
            "source_fingerprint", "projected_fingerprint",
            "source_inventory_digest", "projected_inventory_digest",
        ):
            _id(getattr(self, name), name)
        _generation(self.source_generation, "source_generation")
        _generation(self.projected_generation, "projected_generation")
        self.allowance.__post_init__()
        self.patch_step_fact.__post_init__()
        if (
            self.patch_step_fact.step_index != self.allowance.patch_step_index
            or self.patch_step_fact.step_digest != self.allowance.patch_step_digest
            or self.patch_step_fact.owner_ref not in self.allowance.entry_predecessor_owner_refs
        ):
            raise ValueError("entry liveness binding patch fact differs from allowance")
        source_successors = _canonical_cfg_ref_tuple(
            self.source_owner_successors, "source_owner_successors",
        )
        projected_successors = _canonical_cfg_ref_tuple(
            self.projected_owner_successors, "projected_owner_successors",
        )
        if self.allowance.dispatcher_old_target_ref not in source_successors:
            raise ValueError("entry liveness receipt source preimage omits dispatcher target")
        if self.allowance.replacement_endpoint_ref not in projected_successors:
            raise ValueError("entry liveness receipt projected realization omits replacement")
        if self.allowance.dispatcher_old_target_ref in projected_successors:
            raise ValueError("entry liveness receipt projected realization retains dispatcher")
        if self.source_liveness_safe is not True or self.projected_redirect_realized is not True:
            raise ValueError("entry liveness receipt must seal accepted liveness and realization")
        object.__setattr__(self, "source_owner_successors", source_successors)
        object.__setattr__(self, "projected_owner_successors", projected_successors)
        expected = authority_id((
            "unflatten.entry-endpoint-liveness-binding.v1",
            self.allowance, self.route_proof_id, self.patch_step_fact,
            self.source_fingerprint, self.projected_fingerprint,
            self.source_generation, self.projected_generation,
            self.source_inventory_digest, self.projected_inventory_digest,
            self.source_owner_successors, self.projected_owner_successors,
            self.source_liveness_safe, self.projected_redirect_realized,
        ))
        if self.binding_id != expected:
            raise ValueError("entry liveness binding ID does not match content")


@dataclass(frozen=True, slots=True)
class UseDefFragmentWitness:
    fragment_id: str
    state_identity: StorageIdentity
    redirect_owner_refs: tuple[CfgBlockRef, ...]
    redirect_digest: str
    executed: bool
    fragment_atomic: bool
    actionable_non_state_severance_count: int
    violation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.fragment_id, "fragment_id")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be a StorageIdentity")
        refs = _canonical_cfg_ref_tuple(
            self.redirect_owner_refs, "redirect_owner_refs",
        )
        object.__setattr__(self, "redirect_owner_refs", refs)
        _id(self.redirect_digest, "redirect_digest")
        if not isinstance(self.executed, bool) or not isinstance(self.fragment_atomic, bool):
            raise TypeError("executed and fragment_atomic must be bools")
        _nonnegative(self.actionable_non_state_severance_count, "actionable_non_state_severance_count")
        violations = _tuple(self.violation_ids, "violation_ids", sort=True)
        for value in violations:
            _id(value, "violation_ids item")
        if self.actionable_non_state_severance_count == 0 and violations:
            raise ValueError("violation_ids require actionable non-state severance")
        object.__setattr__(self, "violation_ids", violations)
        if self.executed and self.fragment_atomic and len(violations) != self.actionable_non_state_severance_count:
            raise ValueError("executed atomic use-def witness count must equal violation IDs")


def _anchor_matches_native_scope(
    block_ref: NativeBlockRef | LogicalBlockRef,
    anchor_ea: int,
    instruction_eas: tuple[int, ...],
) -> bool:
    """Accept instruction origins or a physical anchor in an exact native ref."""

    return int(anchor_ea) in instruction_eas or (
        type(block_ref) is NativeBlockRef
        and block_ref.identity.native_ranges.contains(int(anchor_ea))
    )


def _phase_native_origin_subset_preserves_anchor(
    block_ref: CfgBlockRef | None,
    anchor_ea: int | None,
    observed_instruction_eas: tuple[int, ...],
    expected_instruction_eas: tuple[int, ...],
) -> bool:
    """Allow phase-local origin loss only when it retains the canonical anchor.

    A native physical block entry can be the canonical anchor without being an
    instruction origin. In that one case a strict projected/observed subset need not
    contain the anchor. If the canonical anchor is an exact instruction, it
    must remain present in the observed origin subset.

    Total loss is the boundary case of that same subset, not a distinct
    identity failure: a proven fake jump folded away leaves the physical block
    in place with no surviving microinstruction. Its canonical anchor is then
    the block entry, which still belongs to the native reference range, so the
    row still denotes its own catalog block. What that block no longer carries
    is a semantic-coverage question owned by the effect, terminal, and
    topology obligations, which can name the subject they lost.
    """

    if (
        not set(observed_instruction_eas) < set(expected_instruction_eas)
        or anchor_ea is None
    ):
        return False
    if anchor_ea in expected_instruction_eas:
        return anchor_ea in observed_instruction_eas
    return (
        type(block_ref) is NativeBlockRef
        and block_ref.identity.native_ranges.contains(anchor_ea)
    )


def _validate_native_instruction_inventory(
    block_ref: NativeBlockRef | LogicalBlockRef,
    instruction_eas: tuple[int, ...],
) -> None:
    """Cross-bind a row's instruction origins to its stable block identity."""

    if type(block_ref) is NativeBlockRef:
        expected = tuple(sorted(block_ref.identity.exact_instruction_eas))
        if instruction_eas != expected:
            raise ValueError(
                "native instruction origins must exactly match native identity"
            )
        return
    if not instruction_eas:
        raise ValueError("logical block requires instruction origins")


@dataclass(frozen=True, slots=True)
class SourceBlockIdentityWitness:
    block_ref: NativeBlockRef | LogicalBlockRef
    anchor_ea: int
    native_instruction_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        _authority_ref(self.block_ref)
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))
        eas = _tuple(self.native_instruction_eas, "native_instruction_eas", sort=True)
        for ea in eas:
            _ea(ea, "native_instruction_eas item")
        _validate_native_instruction_inventory(self.block_ref, eas)
        if not _anchor_matches_native_scope(self.block_ref, self.anchor_ea, eas):
            raise ValueError(
                "anchor_ea must belong to native_instruction_eas or native identity range"
            )
        object.__setattr__(self, "native_instruction_eas", eas)


@dataclass(frozen=True, slots=True)
class SourceIdentityCatalog:
    native_key: NativePreanalysisKey
    generation: int
    blocks: tuple[SourceBlockIdentityWitness, ...]

    def __post_init__(self) -> None:
        if type(self.native_key) is not NativePreanalysisKey:
            raise TypeError("native_key must be a NativePreanalysisKey")
        _generation(self.generation)
        blocks = _tuple(self.blocks, "blocks", sort=True)
        for block in blocks:
            if type(block) is not SourceBlockIdentityWitness:
                raise TypeError("blocks must contain SourceBlockIdentityWitness values")
            if (
                type(block.block_ref) is NativeBlockRef
                and block.block_ref.identity.native_key != self.native_key
            ):
                raise ValueError("native source witness key must match catalog key")
        refs = tuple(block.block_ref for block in blocks)
        ref_anchor_pairs = tuple((block.block_ref, block.anchor_ea) for block in blocks)
        if (
            len(set(refs)) != len(refs)
            or len(set(ref_anchor_pairs)) != len(ref_anchor_pairs)
        ):
            raise ValueError("source catalog block witnesses must be unique")
        by_anchor: dict[int, tuple[SourceBlockIdentityWitness, ...]] = {}
        for block in blocks:
            by_anchor[block.anchor_ea] = (*by_anchor.get(block.anchor_ea, ()), block)
        for rows in by_anchor.values():
            if len(rows) <= 1:
                continue
            if any(type(row.block_ref) is not NativeBlockRef for row in rows):
                raise ValueError(
                    "shared source anchor requires distinct NativeBlockRef rows"
                )
            if len({row.block_ref for row in rows}) != len(rows):
                raise ValueError("shared source anchor requires distinct native refs")
            if any(
                not row.block_ref.identity.native_ranges.contains(row.anchor_ea)
                for row in rows
            ):
                raise ValueError("shared native anchor is outside native identity range")
        object.__setattr__(self, "blocks", blocks)


@dataclass(frozen=True, slots=True)
class RetirementPlanMember:
    """Exact dispatcher member scope carried by a producer catalog."""

    block_ref: NativeBlockRef | LogicalBlockRef
    anchor_ea: int
    native_instruction_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        _authority_ref(self.block_ref, "block_ref")
        _ea(self.anchor_ea, "anchor_ea")
        eas = _tuple(self.native_instruction_eas, "native_instruction_eas", sort=True)
        for ea in eas:
            _ea(ea, "native_instruction_eas item")
        _validate_native_instruction_inventory(self.block_ref, eas)
        if not _anchor_matches_native_scope(self.block_ref, self.anchor_ea, eas):
            raise ValueError(
                "retirement plan member anchor must belong to instruction origins "
                "or native identity range"
            )
        object.__setattr__(self, "native_instruction_eas", eas)


@dataclass(frozen=True, slots=True)
class DispatcherRetirementCandidate:
    """Producer eligibility evidence; it carries no phase disposition."""

    block_ref: NativeBlockRef | LogicalBlockRef
    anchor_ea: int
    role: str
    evidence_ids: tuple[str, ...]
    source_generation: int
    candidate_id: str

    def __post_init__(self) -> None:
        _authority_ref(self.block_ref, "block_ref")
        _ea(self.anchor_ea, "anchor_ea")
        _text(self.role, "role")
        evidence = _strict_id_tuple(self.evidence_ids, "evidence_ids")
        if not evidence:
            raise ValueError("retirement candidate requires evidence IDs")
        object.__setattr__(self, "evidence_ids", evidence)
        _generation(self.source_generation, "source_generation")
        _id(self.candidate_id, "candidate_id")
        expected = authority_id((
            "unflatten.dispatcher-retirement-candidate.v1",
            self.block_ref, self.anchor_ea, self.role, self.evidence_ids,
            self.source_generation,
        ))
        if self.candidate_id != expected:
            raise ValueError("candidate_id does not match candidate content")


@dataclass(frozen=True, slots=True)
class RetirementCandidateCatalog:
    """Canonical producer catalog: exact plan members plus eligible candidates."""

    catalog_id: str
    source_generation: int
    plan_members: tuple[RetirementPlanMember, ...]
    candidates: tuple[DispatcherRetirementCandidate, ...]

    def __post_init__(self) -> None:
        _id(self.catalog_id, "catalog_id")
        _generation(self.source_generation, "source_generation")
        members = _tuple(self.plan_members, "plan_members", sort=True)
        candidates = _tuple(self.candidates, "candidates", sort=True)
        if not members:
            raise ValueError("retirement candidate catalog must not be empty")
        if any(type(item) is not RetirementPlanMember for item in members):
            raise TypeError("plan_members must contain RetirementPlanMember values")
        if any(type(item) is not DispatcherRetirementCandidate for item in candidates):
            raise TypeError("candidates must contain DispatcherRetirementCandidate values")
        if any(item.source_generation != self.source_generation for item in candidates):
            raise ValueError("retirement candidate generation mismatch")
        member_refs = tuple(item.block_ref for item in members)
        if len(set(member_refs)) != len(member_refs):
            raise ValueError("retirement plan members must be unique")
        candidate_refs = tuple(item.block_ref for item in candidates)
        if len(set(candidate_refs)) != len(candidate_refs):
            raise ValueError("retirement candidates must be unique")
        member_by_ref = {item.block_ref: item for item in members}
        if any(item.block_ref not in member_by_ref for item in candidates):
            raise ValueError("retirement candidate is outside exact plan membership")
        if any(item.anchor_ea != member_by_ref[item.block_ref].anchor_ea for item in candidates):
            raise ValueError("retirement candidate anchor differs from plan member")
        object.__setattr__(self, "plan_members", members)
        object.__setattr__(self, "candidates", candidates)
        expected = authority_id((
            "unflatten.dispatcher-retirement-candidate-catalog.v1",
            self.source_generation, members, candidates,
        ))
        if self.catalog_id != expected:
            raise ValueError("catalog_id does not match candidate catalog content")

    @property
    def member_refs(self) -> tuple[NativeBlockRef | LogicalBlockRef, ...]:
        return tuple(item.block_ref for item in self.plan_members)

    @property
    def candidate_refs(self) -> tuple[NativeBlockRef | LogicalBlockRef, ...]:
        return tuple(item.block_ref for item in self.candidates)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetirementPhaseMember:
    block_ref: NativeBlockRef | LogicalBlockRef
    anchor_ea: int
    classification: RetirementPhaseClassification
    candidate_id: str | None
    candidate_reachable: bool | None
    reason: str
    source_binding: PhaseSubjectBinding
    candidate_binding: PhaseSubjectBinding

    def __new__(cls, *_args: object, **_kwargs: object) -> RetirementPhaseMember:
        raise TypeError("RetirementPhaseMember is binder-owned")

    def __post_init__(self) -> None:
        _authority_ref(self.block_ref, "block_ref")
        _ea(self.anchor_ea, "anchor_ea")
        _enum(self.classification, RetirementPhaseClassification, "classification")
        if self.candidate_id is not None:
            _id(self.candidate_id, "candidate_id")
        if self.candidate_reachable is not None and type(self.candidate_reachable) is not bool:
            raise TypeError("candidate_reachable must be an exact bool or None")
        _text(self.reason, "reason")
        if type(self.source_binding) is not PhaseSubjectBinding:
            raise TypeError("source_binding must be PhaseSubjectBinding")
        if type(self.candidate_binding) is not PhaseSubjectBinding:
            raise TypeError("candidate_binding must be PhaseSubjectBinding")
        self.source_binding.__post_init__()
        self.candidate_binding.__post_init__()
        if (
            self.source_binding.subject.block_ref != self.block_ref
            or self.source_binding.subject.anchor_ea != self.anchor_ea
            or self.candidate_binding.subject != self.source_binding.subject
        ):
            raise ValueError("retirement phase bindings differ from exact member identity")
        if self.source_binding.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("retirement source binding must be producer forecast")
        if self.candidate_binding.phase not in {
            UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        }:
            raise ValueError("retirement candidate binding phase is invalid")
        if self.candidate_binding.status is SubjectBindingStatus.UNIQUE:
            if self.candidate_reachable is None:
                raise ValueError("unique retirement candidate binding requires reachability")
        elif self.candidate_reachable is not None:
            raise ValueError("non-unique retirement candidate binding cannot carry reachability")
        if self.classification is RetirementPhaseClassification.RETAINED and not (
            self.source_binding.status is SubjectBindingStatus.UNIQUE
            and self.candidate_binding.status is SubjectBindingStatus.UNIQUE
            and self.candidate_reachable is True
        ):
            raise ValueError("retained classification disagrees with sealed bindings")
        if self.classification is RetirementPhaseClassification.RETIRED and not (
            self.source_binding.status is SubjectBindingStatus.UNIQUE
            and self.candidate_id is not None
            and (
                self.candidate_binding.status is SubjectBindingStatus.MISSING
                or (
                    self.candidate_binding.status is SubjectBindingStatus.UNIQUE
                    and self.candidate_reachable is False
                )
            )
        ):
            raise ValueError("retired classification disagrees with sealed evidence")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetirementPhaseResult:
    """One immutable/content-addressed transaction result for one phase."""

    result_id: str
    catalog_id: str
    claim_id: str
    phase: UnflattenAuthorityPhase
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    members: tuple[RetirementPhaseMember, ...]

    def __new__(cls, *_args: object, **_kwargs: object) -> RetirementPhaseResult:
        raise TypeError("RetirementPhaseResult is binder-owned")

    def __post_init__(self) -> None:
        _id(self.result_id, "result_id")
        _id(self.catalog_id, "catalog_id")
        _id(self.claim_id, "claim_id")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        members = _tuple(self.members, "members", sort=True)
        if not members or any(type(item) is not RetirementPhaseMember for item in members):
            raise TypeError("members must contain exact RetirementPhaseMember values")
        refs = tuple(item.block_ref for item in members)
        if len(set(refs)) != len(refs):
            raise ValueError("retirement phase members must be unique")
        if any(
            item.source_binding.graph_fingerprint != self.source_fingerprint
            or item.candidate_binding.graph_fingerprint != self.candidate_fingerprint
            or item.source_binding.generation != self.source_generation
            or item.candidate_binding.generation != self.candidate_generation
            or item.candidate_binding.phase is not self.phase
            for item in members
        ):
            raise ValueError("retirement phase bindings are not sealed to phase coordinates")
        object.__setattr__(self, "members", members)
        expected = authority_id((
            "unflatten.dispatcher-retirement-phase.v1", self.catalog_id,
            self.claim_id, self.phase, self.source_fingerprint,
            self.candidate_fingerprint, self.source_generation,
            self.candidate_generation, members,
        ))
        if self.result_id != expected:
            raise ValueError("result_id does not match retirement phase content")

    @property
    def retired_refs(self) -> tuple[NativeBlockRef | LogicalBlockRef, ...]:
        return tuple(item.block_ref for item in self.members if item.classification is RetirementPhaseClassification.RETIRED)

    @property
    def retained_refs(self) -> tuple[NativeBlockRef | LogicalBlockRef, ...]:
        return tuple(item.block_ref for item in self.members if item.classification is RetirementPhaseClassification.RETAINED)

    @property
    def accepted(self) -> bool:
        return all(item.classification in {RetirementPhaseClassification.RETIRED, RetirementPhaseClassification.RETAINED} for item in self.members)


@dataclass(frozen=True, slots=True)
class AuthoritativeHandlerInput:
    block_ref: NativeBlockRef
    anchor_ea: int
    normalized_states: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.block_ref) is not NativeBlockRef:
            raise TypeError("authoritative handler requires a NativeBlockRef")
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))
        states = _tuple(self.normalized_states, "normalized_states", sort=True)
        for state in states:
            _nonnegative(state, "normalized state")
        object.__setattr__(self, "normalized_states", states)


@dataclass(frozen=True, slots=True)
class UnflattenPlanInputCatalog:
    shape: UnflattenPlanShape
    source_entry_ref: NativeBlockRef | LogicalBlockRef
    dispatcher_entry_ref: NativeBlockRef | LogicalBlockRef
    dispatcher_member_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    authoritative_handlers: tuple[AuthoritativeHandlerInput, ...]
    state_identity: StorageIdentity

    def __post_init__(self) -> None:
        _enum(self.shape, UnflattenPlanShape, "shape")
        _authority_ref(self.source_entry_ref, "source_entry_ref")
        _authority_ref(self.dispatcher_entry_ref, "dispatcher_entry_ref")
        members = _tuple(self.dispatcher_member_refs, "dispatcher_member_refs", sort=True)
        for ref in members:
            _authority_ref(ref, "dispatcher_member_refs item")
        if self.dispatcher_entry_ref not in members:
            raise ValueError("dispatcher_member_refs must include dispatcher_entry_ref")
        handlers = _tuple(self.authoritative_handlers, "authoritative_handlers", sort=True)
        for handler in handlers:
            if type(handler) is not AuthoritativeHandlerInput:
                raise TypeError("authoritative_handlers must contain handler inputs")
        handler_keys = tuple((handler.block_ref, handler.anchor_ea) for handler in handlers)
        if len(set(handler_keys)) != len(handler_keys):
            raise ValueError("authoritative_handlers must not repeat a ref and anchor")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be a StorageIdentity")
        object.__setattr__(self, "dispatcher_member_refs", members)
        object.__setattr__(self, "authoritative_handlers", handlers)


@dataclass(frozen=True, slots=True)
class LegacyShadowEntry:
    """One canonical, non-authoritative legacy metadata payload."""

    key: str
    canonical_payload: bytes
    payload_sha256: str

    def __post_init__(self) -> None:
        if type(self.key) is not str or not self.key.strip():
            raise TypeError("key must be a non-empty exact str")
        if self.key not in LEGACY_UNFLATTEN_KEYS:
            raise ValueError("key is not a reserved unflatten metadata key")
        if type(self.canonical_payload) is not bytes or not self.canonical_payload:
            raise TypeError("canonical_payload must be non-empty exact bytes")
        if (
            type(self.payload_sha256) is not str
            or len(self.payload_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.payload_sha256)
        ):
            raise ValueError("payload_sha256 must be a lowercase SHA-256 digest")
        digest = hashlib.sha256(self.canonical_payload).hexdigest()
        if self.payload_sha256 != digest:
            raise ValueError("payload digest does not match canonical_payload")


@dataclass(frozen=True, slots=True)
class LegacyUnflattenShadowEnvelope:
    """Temporary transport for legacy facts; never an authority input."""

    schema_version: Literal[1]
    plan_id: str
    snapshot_id: str
    source_generation: int
    entries: tuple[LegacyShadowEntry, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("unsupported legacy shadow schema")
        if type(self.plan_id) is not str or not self.plan_id.strip():
            raise TypeError("plan_id must be a non-empty exact str")
        if type(self.snapshot_id) is not str or not self.snapshot_id.strip():
            raise TypeError("snapshot_id must be a non-empty exact str")
        if type(self.source_generation) is not int or self.source_generation < 0:
            raise TypeError("source_generation must be a non-negative exact int")
        if type(self.entries) is not tuple:
            raise TypeError("entries must be an exact tuple")
        if not self.entries:
            raise ValueError("legacy shadow envelope must not be empty")
        if any(type(entry) is not LegacyShadowEntry for entry in self.entries):
            raise TypeError("entries must contain LegacyShadowEntry values")
        for entry in self.entries:
            LegacyShadowEntry.__post_init__(entry)
        keys = tuple(entry.key for entry in self.entries)
        if len(set(keys)) != len(keys):
            raise ValueError("legacy shadow entries must have unique keys")
        if keys != tuple(sorted(keys)):
            raise ValueError("legacy shadow entries must be sorted by key")


@dataclass(frozen=True, slots=True)
class ProposedUnflattenContract:
    schema_version: int
    rule_set_version: int
    plan_id: str
    route_evidence: CanonicalSemanticEvidence
    source_identity_catalog: SourceIdentityCatalog
    use_def_witness: UseDefFragmentWitness
    claims: tuple[ProducerUnflattenClaim, ...]
    plan_inputs: UnflattenPlanInputCatalog
    corridor_coverage_forecast: CorridorCoverageForecast | DefaultGapInfeasibilityForecast | None = None
    retirement_candidate_catalog: RetirementCandidateCatalog | None = None
    entry_endpoint_liveness_allowances: tuple[EntryEndpointLivenessAllowance, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or type(self.rule_set_version) is not int
            or self.schema_version != 1
            or self.rule_set_version != 1
        ):
            raise ValueError("unsupported proposal schema or rule-set version")
        _id(self.plan_id, "plan_id")
        if type(self.route_evidence) is not CanonicalSemanticEvidence:
            raise TypeError("route_evidence must be CanonicalSemanticEvidence")
        if type(self.source_identity_catalog) is not SourceIdentityCatalog:
            raise TypeError("source_identity_catalog must be SourceIdentityCatalog")
        if type(self.use_def_witness) is not UseDefFragmentWitness:
            raise TypeError("use_def_witness must be UseDefFragmentWitness")
        if type(self.plan_inputs) is not UnflattenPlanInputCatalog:
            raise TypeError("plan_inputs must be UnflattenPlanInputCatalog")
        if self.retirement_candidate_catalog is not None and type(self.retirement_candidate_catalog) is not RetirementCandidateCatalog:
            raise TypeError("retirement_candidate_catalog must be RetirementCandidateCatalog or None")
        if self.retirement_candidate_catalog is not None:
            if type(self.retirement_candidate_catalog) is not RetirementCandidateCatalog:
                raise TypeError("retirement_candidate_catalog must be RetirementCandidateCatalog or None")
            if self.retirement_candidate_catalog.source_generation != self.source_identity_catalog.generation:
                raise ValueError("retirement candidate catalog generation differs from source catalog")
            if set(self.retirement_candidate_catalog.member_refs) != set(self.plan_inputs.dispatcher_member_refs):
                raise ValueError("retirement candidate catalog is not exact plan membership")
            source_by_ref = {item.block_ref: item for item in self.source_identity_catalog.blocks}
            for member in self.retirement_candidate_catalog.plan_members:
                witness = source_by_ref.get(member.block_ref)
                if witness is None or witness.anchor_ea != member.anchor_ea or witness.native_instruction_eas != member.native_instruction_eas:
                    raise ValueError("retirement candidate member identity drifted")
        allowances = _tuple(
            self.entry_endpoint_liveness_allowances,
            "entry_endpoint_liveness_allowances",
            sort=True,
        )
        if any(type(item) is not EntryEndpointLivenessAllowance for item in allowances):
            raise TypeError("entry endpoint liveness allowances must be closed records")
        if len({item.allowance_id for item in allowances}) != len(allowances):
            raise ValueError("entry endpoint liveness allowance IDs must be unique")
        step_scopes: set[int] = set()
        owner_scopes: set[CfgBlockRef] = set()
        edge_scopes: set[tuple[CfgBlockRef, CfgBlockRef]] = set()
        for allowance in allowances:
            allowance.__post_init__()
            owner = allowance.entry_predecessor_owner_refs[0]
            edge = (
                allowance.dispatcher_old_target_ref,
                allowance.replacement_endpoint_ref,
            )
            if (
                allowance.patch_step_index in step_scopes
                or owner in owner_scopes
                or edge in edge_scopes
            ):
                raise ValueError("entry endpoint liveness allowances overlap a redirect scope")
            step_scopes.add(allowance.patch_step_index)
            owner_scopes.add(owner)
            edge_scopes.add(edge)
        object.__setattr__(self, "entry_endpoint_liveness_allowances", allowances)
        if self.corridor_coverage_forecast is not None:
            if type(self.corridor_coverage_forecast) not in (CorridorCoverageForecast, DefaultGapInfeasibilityForecast):
                raise TypeError("corridor_coverage_forecast must be a closed corridor forecast or None")
            self.corridor_coverage_forecast.__post_init__()
            forecast = (
                self.corridor_coverage_forecast.base_forecast
                if type(self.corridor_coverage_forecast) is DefaultGapInfeasibilityForecast
                else self.corridor_coverage_forecast
            )
            if forecast.plan_id != self.plan_id:
                raise ValueError("corridor forecast belongs to a foreign plan")
            if forecast.source_native_key != self.source_identity_catalog.native_key:
                raise ValueError("corridor forecast native key differs from source catalog")
            if forecast.source_generation != self.source_identity_catalog.generation:
                raise ValueError("corridor forecast generation differs from source catalog")
            if forecast.dispatcher_ref != self.plan_inputs.dispatcher_entry_ref:
                raise ValueError("corridor forecast dispatcher differs from plan input")
            source_blocks = {item.block_ref: item for item in self.source_identity_catalog.blocks}
            dispatcher = source_blocks.get(forecast.dispatcher_ref)
            if dispatcher is None or dispatcher.anchor_ea != forecast.dispatcher_anchor_ea:
                raise ValueError("corridor forecast dispatcher anchor differs from source catalog")
            forecast_nodes = tuple(
                node for path in forecast.paths for node in path.nodes
            ) + tuple(
                node
                for exclusion in forecast.semantic_exclusions
                for node in (
                    exclusion.source,
                    exclusion.feeder,
                    exclusion.prefix,
                    exclusion.root,
                )
                if node is not None
            )
            if any(
                (witness := source_blocks.get(node.block_ref)) is None
                or witness.anchor_ea != node.anchor_ea
                for node in forecast_nodes
            ):
                raise ValueError("corridor forecast node differs from source catalog")
            if any(
                exclusion.state_identity != self.plan_inputs.state_identity
                for exclusion in forecast.semantic_exclusions
            ):
                raise ValueError("corridor semantic exclusion state identity differs from plan")
        if (
            not self.use_def_witness.executed
            or not self.use_def_witness.fragment_atomic
            or self.use_def_witness.actionable_non_state_severance_count
            or self.use_def_witness.violation_ids
        ):
            raise ValueError("proposal requires a clean executed use-def witness")
        claims = _tuple(self.claims, "claims", sort=True)
        if not claims:
            raise ValueError("proposal requires at least one claim")
        for claim in claims:
            if type(claim) not in (RetiredDispatcherInfrastructureClaim, DetachedDeadHandlerComponentClaim, EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim, TerminalCycleBreakClaim):
                raise TypeError("claims must contain producer claims only")
        if len({claim.claim_id for claim in claims}) != len(claims):
            raise ValueError("claims must not contain duplicate IDs")
        object.__setattr__(self, "claims", claims)
        requires_corridor_forecast = (
            self.retirement_candidate_catalog is not None
            or any(type(claim) is RetiredDispatcherInfrastructureClaim for claim in claims)
        )
        if requires_corridor_forecast and self.corridor_coverage_forecast is None:
            raise ValueError("corridor rewrite or retirement proposals require a coverage forecast")
        if self.route_evidence.native_key != self.source_identity_catalog.native_key:
            raise ValueError("proposal route evidence and source catalog key must match")
        if self.route_evidence.generation != self.source_identity_catalog.generation:
            raise ValueError("proposal route evidence and source catalog generation must match")
        if any(claim.source_generation != self.source_identity_catalog.generation for claim in claims):
            raise ValueError("proposal claims must match source catalog generation")
        if self.use_def_witness.state_identity != self.plan_inputs.state_identity:
            raise ValueError("proposal use-def and plan input state identities must match")
        if any(
            type(claim) is ExactInfeasibleEffectClaim
            and claim.state_identity != self.plan_inputs.state_identity
            for claim in claims
        ):
            raise ValueError("exact-effect claim and plan input state identities must match")

        catalog_by_ref = {
            block.block_ref: block for block in self.source_identity_catalog.blocks
        }
        catalog_refs = set(catalog_by_ref)
        for claim in claims:
            for subject in _claim_subjects(claim):
                for ref, anchor in _subject_pairs(subject):
                    witness = catalog_by_ref.get(ref)
                    if type(ref) is LogicalBlockRef and anchor is None:
                        # Exact logical function exits are deliberately
                        # anchorless and close through the selected DAG
                        # endpoint plus source inventory, not native catalog.
                        continue
                    if witness is None:
                        raise ValueError("proposal subject reference is absent from source catalog")
                    if anchor is not None:
                        if (
                            type(claim) is EquivalentSemanticRouteClaim
                            and type(ref) is NativeBlockRef
                        ):
                            # Canonical route claims retain proof-owned
                            # semantic anchors.  The catalog anchor is a
                            # structural block-start coordinate and can
                            # precede the first exact instruction after MBA
                            # partitioning; only the stable identity range is
                            # authoritative for these route endpoints.
                            if not ref.identity.native_ranges.contains(anchor):
                                raise ValueError(
                                    "proposal route anchor is outside source identity"
                                )
                        elif witness.anchor_ea != anchor:
                            raise ValueError("proposal subject anchor disagrees with source catalog")
            if type(claim) is ExactInfeasibleEffectClaim:
                exact_sites = (
                    (claim.source_subject.block_ref, claim.source_write_ea),
                    (claim.predicate_subject.block_ref, claim.predicate_branch_ea),
                    (claim.discarded_effect_subject.block_ref, claim.discarded_effect_ea),
                )
                for ref, ea in exact_sites:
                    witness = catalog_by_ref.get(ref)
                    if witness is None or ea not in witness.native_instruction_eas:
                        raise ValueError("exact claim instruction EA is absent from source witness")
        if any(ref not in catalog_refs for ref in self.use_def_witness.redirect_owner_refs):
            raise ValueError("proposal use-def reference is absent from source catalog")
        plan_refs = (
            self.plan_inputs.source_entry_ref,
            self.plan_inputs.dispatcher_entry_ref,
            *self.plan_inputs.dispatcher_member_refs,
            *(handler.block_ref for handler in self.plan_inputs.authoritative_handlers),
        )
        if any(ref not in catalog_refs for ref in plan_refs):
            raise ValueError("proposal plan input reference is absent from source catalog")
        for handler in self.plan_inputs.authoritative_handlers:
            witness = catalog_by_ref.get(handler.block_ref)
            if witness is None or witness.anchor_ea != handler.anchor_ea:
                raise ValueError("proposal handler anchor disagrees with source catalog")

        claim_kinds = {claim.kind for claim in claims}
        dispatcher_member_refs = set(self.plan_inputs.dispatcher_member_refs)
        candidate_refs = {
            member.locator.block_ref
            for claim in claims
            if type(claim) is RetiredDispatcherInfrastructureClaim
            for member in claim.member_subjects
        }
        retirement_claims = tuple(
            claim for claim in claims
            if type(claim) is RetiredDispatcherInfrastructureClaim
        )
        if retirement_claims:
            if len(retirement_claims) != 1:
                raise ValueError("proposal requires one retirement candidate claim")
            if (
                self.retirement_candidate_catalog is None
                or retirement_claims[0].candidate_catalog
                != self.retirement_candidate_catalog
            ):
                raise ValueError("retirement claim must share the proposal candidate catalog")
            if set(candidate_refs) != set(
                self.retirement_candidate_catalog.candidate_refs
            ):
                raise ValueError("proposal retirement candidates disagree with catalog")
        elif self.retirement_candidate_catalog is not None:
            raise ValueError("proposal candidate catalog has no retirement claim")
        if not candidate_refs <= dispatcher_member_refs:
            raise ValueError("retirement candidates must be a subset of dispatcher members")
        handler_refs = {
            handler.block_ref for handler in self.plan_inputs.authoritative_handlers
        }
        for detached_claim in (
            claim
            for claim in claims
            if type(claim) is DetachedDeadHandlerComponentClaim
        ):
            claimed_handler_refs = {
                subject.block_ref
                for subject in (
                    *detached_claim.dead_handler_subjects,
                    *detached_claim.retained_handler_subjects,
                )
            }
            if claimed_handler_refs != handler_refs:
                raise ValueError(
                    "detached handler partitions must cover the exact authoritative handler catalog"
                )
            if (
                detached_claim.dispatcher_subject.block_ref
                != self.plan_inputs.dispatcher_entry_ref
            ):
                raise ValueError(
                    "detached dispatcher must match the exact plan dispatcher entry"
                )
        if handler_refs & candidate_refs:
            raise ValueError("authoritative handlers must be disjoint from retirement candidates")
        if self.plan_inputs.shape is UnflattenPlanShape.EXACT_EFFECT_ONLY:
            if (
                claim_kinds != {UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT}
                or candidate_refs
            ):
                raise ValueError("exact-effect-only plan has incompatible claim families")
        elif self.plan_inputs.shape is UnflattenPlanShape.PARTIAL_REWRITE:
            if not claim_kinds.intersection({
                UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
                UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
                UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
                UnflattenClaimKind.DETACHED_DEAD_HANDLER_COMPONENT,
            }):
                raise ValueError("partial rewrite requires route, retirement, or terminal-cycle claims")
        elif self.plan_inputs.shape is UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT:
            if UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE not in claim_kinds:
                raise ValueError("full dispatcher retirement requires a retirement claim")
            if candidate_refs != dispatcher_member_refs:
                raise ValueError("full retirement intent requires every dispatcher member candidate")

@dataclass(frozen=True, slots=True)
class ObligationKey:
    subject: SemanticSubjectRef
    dimension: SafetyDimension

    def __post_init__(self) -> None:
        if type(self.subject) is not SemanticSubjectRef:
            raise TypeError("subject must be a SemanticSubjectRef")
        _enum(self.dimension, SafetyDimension, "dimension")


@dataclass(frozen=True, slots=True)
class AuthorityJustification:
    justification_id: str
    rule: UnflattenJustificationRule
    premise_ids: tuple[str, ...]
    conclusion: ObligationKey
    polarity: EvidencePolarity
    phase: UnflattenAuthorityPhase
    claim_id: str | None = None

    def __post_init__(self) -> None:
        _id(self.justification_id, "justification_id")
        _enum(self.rule, UnflattenJustificationRule, "rule")
        premises = _tuple(self.premise_ids, "premise_ids", sort=True)
        for premise in premises:
            _id(premise, "premise_id")
        object.__setattr__(self, "premise_ids", premises)
        if type(self.conclusion) is not ObligationKey:
            raise TypeError("conclusion must be an ObligationKey")
        _enum(self.polarity, EvidencePolarity, "polarity")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        if self.claim_id is not None:
            _id(self.claim_id, "claim_id")
        if self.justification_id != justification_id(self):
            raise ValueError("justification_id does not match canonical content")


@dataclass(frozen=True, slots=True)
class ObligationEvidenceCell:
    key: ObligationKey
    phase: UnflattenAuthorityPhase
    supporting_justification_ids: tuple[str, ...]
    refuting_justification_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.key) is not ObligationKey:
            raise TypeError("key must be an ObligationKey")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        for name in ("supporting_justification_ids", "refuting_justification_ids"):
            values = _tuple(getattr(self, name), name, sort=True)
            for value in values:
                _id(value, f"{name} item")
            object.__setattr__(self, name, values)
        if set(self.supporting_justification_ids) & set(self.refuting_justification_ids):
            raise ValueError("supporting and refuting justification IDs must be disjoint")

    @property
    def state(self) -> ObligationState:
        support = bool(self.supporting_justification_ids)
        refute = bool(self.refuting_justification_ids)
        if support and refute:
            return ObligationState.INCONSISTENT
        if support:
            return ObligationState.SATISFIED
        if refute:
            return ObligationState.VIOLATED
        return ObligationState.UNPROVEN


def _strict_id_tuple(values: object, label: str) -> tuple[str, ...]:
    """Validate an already-materialized canonical ID tuple without coercion."""

    if type(values) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    if any(type(value) is not str for value in values):
        raise TypeError(f"{label} must contain exact strings")
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be sorted and unique")
    for value in values:
        _id(value, f"{label} item")
    return values


def _strict_enum_tuple(
    values: object, enum_type: type[Enum], label: str,
) -> tuple[Enum, ...]:
    if type(values) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    if any(type(value) is not enum_type for value in values):
        raise TypeError(f"{label} must contain {enum_type.__name__} values")
    if values != tuple(sorted(set(values), key=lambda value: value.value)):
        raise ValueError(f"{label} must be sorted and unique")
    return values


_LOSS_RULE_KIND = {
    UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN: SemanticLossKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
    UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN: SemanticLossKind.EQUIVALENT_SEMANTIC_ROUTE,
    UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN: SemanticLossKind.EXACT_INFEASIBLE_EFFECT,
    UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN: SemanticLossKind.TERMINAL_CYCLE_BREAK,
    UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN: SemanticLossKind.LOCAL_ALIAS_SCALARIZATION,
    UnflattenJustificationRule.DETACHED_COMPONENT_PROVEN: SemanticLossKind.DETACHED_DEAD_HANDLER_COMPONENT,
}
_LOSS_RULE_CLAIMS = {
    UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN: (RetiredDispatcherInfrastructureClaim,),
    UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN: (EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim),
    UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN: (ExactInfeasibleEffectClaim,),
    UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN: (TerminalCycleBreakClaim,),
    UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN: (LocalAliasEffectScalarizationClaim,),
    UnflattenJustificationRule.DETACHED_COMPONENT_PROVEN: (DetachedDeadHandlerComponentClaim,),
}


def _join_semantic_loss_kinds(
    kinds: tuple[SemanticLossKind, ...],
) -> SemanticLossKind:
    """Join independent typed allowances owned by one physical source row."""

    if type(kinds) is not tuple or any(
        type(kind) is not SemanticLossKind for kind in kinds
    ):
        raise TypeError("semantic loss kinds must be an exact enum tuple")
    canonical = tuple(sorted(set(kinds), key=lambda kind: kind.value))
    if not canonical:
        return SemanticLossKind.UNCLASSIFIED
    if any(
        kind in {
            SemanticLossKind.UNCLASSIFIED,
            SemanticLossKind.CONFLICTING,
            SemanticLossKind.COMPOSITE_ALLOWED,
        }
        for kind in canonical
    ):
        raise ValueError("only atomic allowed loss kinds may be joined")
    return (
        canonical[0]
        if len(canonical) == 1
        else SemanticLossKind.COMPOSITE_ALLOWED
    )


def _semantic_loss_source_subject_ids(case: SemanticSafetyCase) -> tuple[str, ...]:
    """Return the complete canonical block-owner domain for a loss ledger.

    A physical source block owns both its structural disappearance and every
    semantic effect transition at that block.  A scalarized STORE therefore
    remains a loss-ledger row even though the surrounding source block has a
    unique candidate binding.  This is deliberately a projection of the
    sealed case evidence, not another evaluator or claim validator.
    """
    subjects = {item.subject_id: item for item in case.subjects}
    bindings = {item.subject.subject_id: item for item in case.bindings}
    structural_subject_ids = {
        item.key.subject.subject_id
        for item in case.obligation_index.cells
        if item.key.dimension is SafetyDimension.STRUCTURAL_ACCOUNTING
    }
    retired_refs = set(
        case.retirement_phase_result.retired_refs
        if case.retirement_phase_result is not None
        else ()
    )
    semantic_delta_refs = {
        evidence.subject.block_ref
        for evidence in case.evidence
        if (
            evidence.subject.role is SemanticSubjectRole.EFFECT_SITE
            and evidence.subject.block_ref is not None
            and type(evidence.payload) is EffectSiteEvidencePayload
            and evidence.payload.effect_subject_id == evidence.subject.subject_id
            and not evidence.payload.preserved
        )
    }
    return tuple(sorted(
        subject_id
        for subject_id in case.source_subject_ids
        if (
            (subject := subjects.get(subject_id)) is not None
            and subject.role is SemanticSubjectRole.SOURCE_CATALOG_BLOCK
            and (binding := bindings.get(subject_id)) is not None
            and subject_id in structural_subject_ids
            and (
                binding.status is SubjectBindingStatus.MISSING
                or subject.block_ref in retired_refs
                or subject.block_ref in semantic_delta_refs
            )
        )
    ))


def _semantic_loss_effect_subject_ids(
    case: SemanticSafetyCase,
    source_subject: SemanticSubjectRef,
) -> tuple[str, ...]:
    """Return non-preserved effect-site subjects owned by one source block."""
    return tuple(sorted({
        evidence.subject.subject_id
        for evidence in case.evidence
        if (
            evidence.subject.role is SemanticSubjectRole.EFFECT_SITE
            and evidence.subject.block_ref == source_subject.block_ref
            and type(evidence.payload) is EffectSiteEvidencePayload
            and evidence.payload.effect_subject_id == evidence.subject.subject_id
            and not evidence.payload.preserved
        )
    }))


@dataclass(frozen=True, slots=True)
class SemanticLossRow:
    """One canonical source-block classification of structural or effect loss."""

    case: SemanticSafetyCase
    source_subject: SemanticSubjectRef
    source_binding: PhaseSubjectBinding
    candidate_binding: PhaseSubjectBinding
    structural_obligation: ObligationEvidenceCell
    relevant_semantic_obligations: tuple[ObligationEvidenceCell, ...]
    justifications: tuple[AuthorityJustification, ...]
    evidence: tuple[AuthorityEvidence, ...]
    claims: tuple[UnflattenClaim, ...]

    def __post_init__(self) -> None:
        if type(self.case) is not SemanticSafetyCase:
            raise TypeError("case must be a SemanticSafetyCase")
        # ``SemanticLossRow`` is minted only from an already-validated case.
        # Replaying the complete case here makes ledger construction O(rows x
        # case-size) and does not add a new authority boundary.  The unified
        # gate validates the case occurrence once after the full ledger exists.
        if self.case.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("semantic loss rows require a projected or observed case")
        if type(self.source_subject) is not SemanticSubjectRef:
            raise TypeError("source_subject must be a SemanticSubjectRef")
        source_subject_ids = set(self.case.source_subject_ids)
        if self.source_subject.subject_id not in source_subject_ids:
            raise ValueError("loss row subject must belong to the case source partition")
        if self.source_subject.role is not SemanticSubjectRole.SOURCE_CATALOG_BLOCK:
            raise ValueError("loss rows must be owned by canonical source blocks")
        case_subjects = {subject.subject_id: subject for subject in self.case.subjects}
        if case_subjects.get(self.source_subject.subject_id) != self.source_subject:
            raise ValueError("loss row source subject must be the exact case subject")
        case_source_bindings = {
            binding.subject.subject_id: binding for binding in self.case.source_bindings
        }
        if case_source_bindings.get(self.source_subject.subject_id) != self.source_binding:
            raise ValueError("loss row source binding must be the exact case source binding")
        case_bindings = {binding.subject.subject_id: binding for binding in self.case.bindings}
        if case_bindings.get(self.source_subject.subject_id) != self.candidate_binding:
            raise ValueError("loss row candidate binding must be the exact case binding")
        if type(self.source_binding) is not PhaseSubjectBinding:
            raise TypeError("source_binding must be a PhaseSubjectBinding")
        if self.source_binding.subject != self.source_subject:
            raise ValueError("source binding must identify source_subject")
        if (
            self.source_binding.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST
            or self.source_binding.status is not SubjectBindingStatus.UNIQUE
        ):
            raise ValueError("source binding must be a unique producer binding")
        if type(self.candidate_binding) is not PhaseSubjectBinding:
            raise TypeError("candidate_binding must be a PhaseSubjectBinding")
        retired_phase = self.case.retirement_phase_result
        phase_retired = (
            retired_phase is not None
            and any(
                item.block_ref == self.source_subject.block_ref
                and item.classification is RetirementPhaseClassification.RETIRED
                for item in retired_phase.members
            )
        )
        semantic_effect_subject_ids = _semantic_loss_effect_subject_ids(
            self.case, self.source_subject,
        )
        if (
            self.candidate_binding.status is not SubjectBindingStatus.MISSING
            and not phase_retired
            and not semantic_effect_subject_ids
        ):
            raise ValueError(
                "semantic loss rows require a missing candidate, sealed retired phase row, "
                "or owned semantic effect delta"
            )
        if self.candidate_binding.subject != self.source_subject:
            raise ValueError("candidate binding must identify source_subject")
        if type(self.structural_obligation) is not ObligationEvidenceCell:
            raise TypeError("structural_obligation must be an ObligationEvidenceCell")
        if self.structural_obligation.key.subject != self.source_subject:
            raise ValueError("structural obligation must identify source_subject")
        if self.structural_obligation.key.dimension is not SafetyDimension.STRUCTURAL_ACCOUNTING:
            raise ValueError("structural obligation must be STRUCTURAL_ACCOUNTING")
        if self.structural_obligation.phase is not self.candidate_binding.phase:
            raise ValueError("structural obligation phase must match candidate binding")
        case_cells = {
            cell.key: cell for cell in self.case.obligation_index.cells
        }
        if case_cells.get(self.structural_obligation.key) != self.structural_obligation:
            raise ValueError("structural obligation must be the exact case cell")
        if type(self.relevant_semantic_obligations) is not tuple:
            raise TypeError("relevant_semantic_obligations must be an exact tuple")
        semantic = self.relevant_semantic_obligations
        if any(type(cell) is not ObligationEvidenceCell for cell in semantic):
            raise TypeError("relevant_semantic_obligations must contain obligation cells")
        if any(
            cell.key.dimension is SafetyDimension.STRUCTURAL_ACCOUNTING
            or cell.phase is not self.candidate_binding.phase
            or (
                cell.key.subject != self.source_subject
                and cell.key.subject.subject_id not in semantic_effect_subject_ids
            )
            for cell in semantic
        ):
            raise ValueError("semantic obligation cells must belong to the canonical owner")
        if semantic != tuple(sorted(
            semantic,
            key=lambda cell: (cell.key.subject.subject_id, cell.key.dimension.value),
        )):
            raise ValueError("relevant semantic obligations must be in canonical order")
        if len({cell.key for cell in semantic}) != len(semantic):
            raise ValueError("relevant semantic obligations must be unique")
        expected_semantic = tuple(sorted(
            (
                cell for cell in self.case.obligation_index.cells
                if (
                    cell.key.dimension is not SafetyDimension.STRUCTURAL_ACCOUNTING
                    and (
                        cell.key.subject == self.source_subject
                        or cell.key.subject.subject_id in semantic_effect_subject_ids
                    )
                )
            ),
            key=lambda cell: (cell.key.subject.subject_id, cell.key.dimension.value),
        ))
        if semantic != expected_semantic:
            raise ValueError("semantic obligations must be the exact case cells")
        expected_supporting = tuple(sorted({item for cell in (self.structural_obligation, *semantic) for item in cell.supporting_justification_ids}))
        expected_refuting = tuple(sorted({item for cell in (self.structural_obligation, *semantic) for item in cell.refuting_justification_ids}))
        if type(self.justifications) is not tuple or any(type(item) is not AuthorityJustification for item in self.justifications):
            raise TypeError("justifications must contain exact AuthorityJustification values")
        justifications = tuple(sorted(self.justifications, key=lambda item: item.justification_id))
        if justifications != self.justifications:
            raise ValueError("justifications must be in canonical ID order")
        actual_ids = tuple(item.justification_id for item in justifications)
        if actual_ids != tuple(sorted(set((*expected_supporting, *expected_refuting)))):
            raise ValueError("justifications must exactly cover obligation cell IDs")
        if set(expected_supporting) & set(expected_refuting):
            raise ValueError("supporting and refuting justification IDs must be disjoint")
        relevant_keys = {self.structural_obligation.key, *(cell.key for cell in semantic)}
        if any(item.conclusion not in relevant_keys or item.phase is not self.candidate_binding.phase for item in justifications):
            raise ValueError("justifications must conclude the exact relevant cells")
        case_justifications = {
            item.justification_id: item for item in self.case.justifications
        }
        if tuple(case_justifications[item.justification_id] for item in justifications) != justifications:
            raise ValueError("justifications must be the exact case records")
        expected_evidence_ids = tuple(sorted({premise for item in justifications for premise in item.premise_ids}))
        if type(self.evidence) is not tuple or any(type(item) is not AuthorityEvidence for item in self.evidence):
            raise TypeError("evidence must contain exact AuthorityEvidence values")
        evidence = tuple(sorted(self.evidence, key=lambda item: item.evidence_id))
        if evidence != self.evidence or tuple(item.evidence_id for item in evidence) != expected_evidence_ids:
            raise ValueError("evidence must exactly cover justification premises")
        case_evidence = {item.evidence_id: item for item in self.case.evidence}
        if tuple(case_evidence[item.evidence_id] for item in evidence) != evidence:
            raise ValueError("evidence must be the exact case records")
        evidence_ids = set(expected_evidence_ids)
        if any(premise not in evidence_ids for item in justifications for premise in item.premise_ids):
            raise ValueError("justification premise is outside exact row evidence")
        expected_claim_ids = tuple(sorted({item.claim_id for item in justifications if item.claim_id is not None}))
        claim_types = (
            RetiredDispatcherInfrastructureClaim, DetachedDeadHandlerComponentClaim, EquivalentSemanticRouteClaim,
            ExactInfeasibleEffectClaim, LocalAliasEffectScalarizationClaim,
            TerminalCycleBreakClaim,
        )
        if type(self.claims) is not tuple or any(type(item) not in claim_types for item in self.claims):
            raise TypeError("claims must contain closed claim values")
        claims = tuple(sorted(self.claims, key=lambda item: item.claim_id))
        if claims != self.claims or tuple(item.claim_id for item in claims) != expected_claim_ids:
            raise ValueError("claims must exactly cover justification claim IDs")
        case_claims = {item.claim_id: item for item in self.case.claims}
        if tuple(case_claims[item.claim_id] for item in claims) != claims:
            raise ValueError("claims must be the exact case records")
        object.__setattr__(self, "justifications", justifications)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "claims", claims)

    @property
    def candidate_serial(self) -> int | None:
        return self.candidate_binding.serial

    @property
    def candidate_anchor_ea(self) -> int | None:
        return self.candidate_binding.anchor_ea

    @property
    def source_serial(self) -> int:
        return self.source_binding.serial  # type: ignore[return-value]

    @property
    def source_anchor_ea(self) -> int:
        return self.source_binding.anchor_ea  # type: ignore[return-value]

    @property
    def anchored_location(self) -> str | None:
        return f"blk{self.source_serial}@0x{self.source_anchor_ea:x}"

    @property
    def source(self) -> SemanticSubjectRef:
        return self.source_subject

    @property
    def binding(self) -> PhaseSubjectBinding:
        return self.candidate_binding

    @property
    def supporting_justification_ids(self) -> tuple[str, ...]:
        return tuple(item.justification_id for item in self.justifications if item.polarity is EvidencePolarity.SUPPORTS)

    @property
    def refuting_justification_ids(self) -> tuple[str, ...]:
        return tuple(item.justification_id for item in self.justifications if item.polarity is EvidencePolarity.REFUTES)

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(item.evidence_id for item in self.evidence)

    @property
    def claim_ids(self) -> tuple[str, ...]:
        return tuple(item.claim_id for item in self.claims)

    @property
    def rules(self) -> tuple[UnflattenJustificationRule, ...]:
        return tuple(sorted({item.rule for item in self.justifications}, key=lambda item: item.value))

    def _derived_kind(self) -> SemanticLossKind:
        cells = (self.structural_obligation, *self.relevant_semantic_obligations)
        # A sealed missing effect with no supporting claim is deliberately a
        # complete, forbidden classification.  Generic effect-gate evidence
        # also refutes that loss, which can make the effect cell
        # INCONSISTENT; it must not obscure the more useful UNCLASSIFIED
        # verdict or turn it into an apparent competing authority.
        if any(
            type(item.payload) is EffectSiteEvidencePayload
            and not item.payload.preserved
            and item.payload.effect_subject_id == self.source_subject.subject_id
            for item in self.evidence
        ) and not self.claims:
            return SemanticLossKind.UNCLASSIFIED
        if any(cell.state is ObligationState.INCONSISTENT for cell in cells):
            return SemanticLossKind.CONFLICTING
        if any(cell.state is not ObligationState.SATISFIED for cell in cells):
            return SemanticLossKind.UNCLASSIFIED
        if any(
            item.polarity is EvidencePolarity.REFUTES and item.claim_id is not None
            for item in self.justifications
        ):
            return SemanticLossKind.CONFLICTING
        supporting = [item for item in self.justifications if item.polarity is EvidencePolarity.SUPPORTS and item.claim_id is not None]
        claims = {claim.claim_id: claim for claim in self.claims}
        kinds: set[SemanticLossKind] = set()
        for item in supporting:
            expected = _LOSS_RULE_CLAIMS.get(item.rule)
            claim = claims.get(item.claim_id)
            if expected is None or claim is None or type(claim) not in expected:
                return SemanticLossKind.CONFLICTING
            kinds.add(_LOSS_RULE_KIND[item.rule])
        return _join_semantic_loss_kinds(tuple(kinds))

    @property
    def classification_kinds(self) -> tuple[SemanticLossKind, ...]:
        """Return every atomic allowance contributing to this owner row."""

        derived = self._derived_kind()
        if derived in {
            SemanticLossKind.UNCLASSIFIED,
            SemanticLossKind.CONFLICTING,
        }:
            return (derived,)
        kinds = tuple(sorted({
            _LOSS_RULE_KIND[item.rule]
            for item in self.justifications
            if item.polarity is EvidencePolarity.SUPPORTS
            and item.claim_id is not None
            and item.rule in _LOSS_RULE_KIND
        }, key=lambda kind: kind.value))
        if not kinds:
            raise ValueError("allowed semantic loss row lacks atomic classifications")
        if _join_semantic_loss_kinds(kinds) is not derived:
            raise ValueError("semantic loss row classifications disagree with joined kind")
        return kinds

    @property
    def structural_cell(self) -> ObligationEvidenceCell:
        return self.structural_obligation

    @property
    def semantic_obligation_cells(self) -> tuple[ObligationEvidenceCell, ...]:
        return self.relevant_semantic_obligations

    @property
    def relevant_semantic_obligation_cells(self) -> tuple[ObligationEvidenceCell, ...]:
        return self.relevant_semantic_obligations

    @property
    def classification(self) -> SemanticLossKind:
        return self._derived_kind()

    @property
    def kind(self) -> SemanticLossKind:
        return self._derived_kind()


@dataclass(frozen=True, slots=True)
class SemanticLossLedger:
    """Canonical read-only semantic-loss projection for one safety case."""

    case: SemanticSafetyCase
    authority_id: str
    case_id: str
    phase: UnflattenAuthorityPhase
    source_fingerprint: str
    candidate_fingerprint: str
    rows: tuple[SemanticLossRow, ...]
    ledger_id: str

    def __post_init__(self) -> None:
        if type(self.case) is not SemanticSafetyCase:
            raise TypeError("case must be a SemanticSafetyCase")
        # The case is an exact parent occurrence, validated once by the gate.
        # Do not recursively replay its content for every ledger carrier.
        _id(self.authority_id, "authority_id")
        _id(self.case_id, "case_id")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _id(self.ledger_id, "ledger_id")
        if type(self.rows) is not tuple:
            raise TypeError("rows must be an exact tuple")
        if any(type(row) is not SemanticLossRow for row in self.rows):
            raise TypeError("rows must contain SemanticLossRow values")
        if any(row.case is not self.case for row in self.rows):
            raise ValueError("ledger rows must belong to the exact case")
        if (
            self.authority_id != self.case.authority_id
            or self.case_id != self.case.case_id
            or self.phase is not self.case.phase
            or self.source_fingerprint != self.case.source_fingerprint
            or self.candidate_fingerprint != self.case.candidate_fingerprint
        ):
            raise ValueError("ledger metadata must match its exact case")
        if self.rows != tuple(sorted(self.rows, key=lambda row: row.source_subject.subject_id)):
            raise ValueError("rows must be in source subject order")
        if len({row.source_subject.subject_id for row in self.rows}) != len(self.rows):
            raise ValueError("rows must contain unique source subjects")
        if any(row.candidate_binding.phase is not self.phase for row in self.rows):
            raise ValueError("row binding phase must match ledger phase")
        # A ledger is a transaction-owned *complete classification*, not a
        # caller-selectable collection of allowed rows.  Its ID seals row
        # content, but that alone would allow an omitted subset to be reminted
        # with a different valid content ID.  Derive the complete loss domain
        # from the exact immutable case and require the ledger to cover it.
        # This mirrors the evaluator's row-domain predicate without importing
        # the evaluator (the model remains the dependency root).
        expected_subject_ids = _semantic_loss_source_subject_ids(self.case)
        actual_subject_ids = tuple(row.source_subject.subject_id for row in self.rows)
        if actual_subject_ids != expected_subject_ids:
            raise ValueError("ledger rows must completely classify the exact case loss domain")
        expected_ledger_id = authority_id((
            "unflatten.semantic-loss-ledger.v1", self.case_id,
            tuple(
                (
                    row.source_subject.subject_id,
                    tuple(kind.value for kind in row.classification_kinds),
                    tuple(item.justification_id for item in row.justifications),
                    tuple(item.evidence_id for item in row.evidence),
                    tuple(item.claim_id for item in row.claims),
                )
                for row in self.rows
            ),
        ))
        if self.ledger_id != expected_ledger_id:
            raise ValueError("ledger ID does not seal canonical rows")

    @property
    def allowed(self) -> tuple[SemanticLossRow, ...]:
        return tuple(row for row in self.rows if row.kind is not SemanticLossKind.UNCLASSIFIED and row.kind is not SemanticLossKind.CONFLICTING)

    @property
    def unclassified(self) -> tuple[SemanticLossRow, ...]:
        return tuple(row for row in self.rows if row.kind is SemanticLossKind.UNCLASSIFIED)

    @property
    def conflicting(self) -> tuple[SemanticLossRow, ...]:
        return tuple(row for row in self.rows if row.kind is SemanticLossKind.CONFLICTING)

    @property
    def allowed_rows(self) -> tuple[SemanticLossRow, ...]:
        return self.allowed

    @property
    def unclassified_rows(self) -> tuple[SemanticLossRow, ...]:
        return self.unclassified

    @property
    def conflicting_rows(self) -> tuple[SemanticLossRow, ...]:
        return self.conflicting

    @property
    def lost_subject_ids(self) -> tuple[str, ...]:
        return tuple(row.source_subject.subject_id for row in self.rows)


@dataclass(frozen=True, slots=True)
class ObservedSemanticLossDelta:
    """Observed-only loss rows relative to one projected case."""

    authority_id: str
    source_fingerprint: str
    projected_case_id: str
    observed_case_id: str
    projected_ledger_id: str
    observed_ledger_id: str
    rows: tuple[SemanticLossRow, ...]
    delta_id: str

    def __post_init__(self) -> None:
        _id(self.authority_id, "authority_id")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.projected_case_id, "projected_case_id")
        _id(self.observed_case_id, "observed_case_id")
        _id(self.projected_ledger_id, "projected_ledger_id")
        _id(self.observed_ledger_id, "observed_ledger_id")
        _id(self.delta_id, "delta_id")
        if type(self.rows) is not tuple:
            raise TypeError("rows must be an exact tuple")
        if any(type(row) is not SemanticLossRow for row in self.rows):
            raise TypeError("rows must contain SemanticLossRow values")
        if self.rows != tuple(sorted(self.rows, key=lambda row: row.source_subject.subject_id)):
            raise ValueError("rows must be in source subject order")
        if len({row.source_subject.subject_id for row in self.rows}) != len(self.rows):
            raise ValueError("rows must contain unique source subjects")
        expected_delta_id = authority_id((
            "unflatten.observed-loss-delta.v1",
            self.projected_ledger_id,
            self.observed_ledger_id,
            tuple(
                (
                    row.source_subject.subject_id,
                    tuple(kind.value for kind in row.classification_kinds),
                    tuple(item.justification_id for item in row.justifications),
                    tuple(item.evidence_id for item in row.evidence),
                    tuple(item.claim_id for item in row.claims),
                )
                for row in self.rows
            ),
        ))
        if self.delta_id != expected_delta_id:
            raise ValueError("delta ID does not seal canonical rows")

    @property
    def observed_only_rows(self) -> tuple[SemanticLossRow, ...]:
        return self.rows

    @property
    def lost_subject_ids(self) -> tuple[str, ...]:
        return tuple(row.source_subject.subject_id for row in self.rows)

    @property
    def projected_phase(self) -> UnflattenAuthorityPhase:
        return UnflattenAuthorityPhase.PROJECTED_PREFLIGHT

    @property
    def observed_phase(self) -> UnflattenAuthorityPhase:
        return UnflattenAuthorityPhase.OBSERVED_POST_APPLY


@dataclass(frozen=True, slots=True, init=False)
class ObligationEvidenceIndex:
    cells: tuple[ObligationEvidenceCell, ...]
    _token: object = dataclass_field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if getattr(self, "_token", None) is not _OBLIGATION_INDEX_TOKEN:
            raise TypeError("obligation index is evaluator-owned")
        cells = _tuple(self.cells, "cells")
        if any(type(cell) is not ObligationEvidenceCell for cell in cells):
            raise TypeError("cells must contain ObligationEvidenceCell values")
        if len({cell.key for cell in cells}) != len(cells):
            raise ValueError("obligation index keys must be unique")
        object.__setattr__(self, "cells", cells)


@dataclass(frozen=True, slots=True)
class FailedObligation:
    key: ObligationKey
    state: ObligationState

    def __post_init__(self) -> None:
        if type(self.key) is not ObligationKey:
            raise TypeError("key must be an ObligationKey")
        _enum(self.state, ObligationState, "state")
        if self.state is ObligationState.SATISFIED:
            raise ValueError("failed obligation cannot be satisfied")


@dataclass(frozen=True, slots=True)
class PhaseBuildMetrics:
    phase: UnflattenAuthorityPhase
    source_inventory_builds: int
    candidate_inventory_builds: int
    inventory_ms: float

    def __post_init__(self) -> None:
        if type(self.phase) is not UnflattenAuthorityPhase:
            raise TypeError("phase must be UnflattenAuthorityPhase")
        _inventory_nonnegative(self.source_inventory_builds, "source_inventory_builds")
        _inventory_nonnegative(self.candidate_inventory_builds, "candidate_inventory_builds")
        expected = {
            UnflattenAuthorityPhase.PROJECTED_PREFLIGHT: (1, 1),
            UnflattenAuthorityPhase.OBSERVED_POST_APPLY: (0, 1),
        }.get(self.phase)
        if expected is None or (self.source_inventory_builds, self.candidate_inventory_builds) != expected:
            raise ValueError("phase inventory build counts are not exact")
        if type(self.inventory_ms) not in (int, float) or isinstance(self.inventory_ms, bool):
            raise TypeError("inventory_ms must be a finite nonnegative number")
        if not math.isfinite(float(self.inventory_ms)) or self.inventory_ms < 0:
            raise ValueError("inventory_ms must be a finite nonnegative number")


def validate_phase_build_metrics(value: object) -> PhaseBuildMetrics:
    """Revalidate one phase metric record without rebuilding it."""

    if type(value) is not PhaseBuildMetrics:
        raise TypeError("phase_build_metrics must be PhaseBuildMetrics")
    value.__post_init__()
    return value


@dataclass(frozen=True, slots=True)
class SemanticGraphInventory:
    phase: UnflattenAuthorityPhase
    graph_fingerprint: str
    generation: int
    blocks: tuple[InventoryBlockObservation, ...]
    subjects: tuple[SemanticSubjectRef, ...]
    bindings: tuple[PhaseSubjectBinding, ...]
    effects: tuple[InventoryEffectSite, ...]
    terminals: tuple[InventoryTerminalSite, ...]
    topology: tuple[InventoryTopologyIncidence, ...]
    inventory_digest: str
    reachable_serials: tuple[int, ...]
    entry_serial: int
    source_subject_ids: tuple[str, ...]
    function_ea: int
    observed_route_topology_occurrences: tuple[ObservedRouteTopologyOccurrence, ...] = ()
    observed_lowered_conditional_topology_occurrences: tuple[
        ObservedLoweredConditionalTopologyOccurrence, ...
    ] = ()

    @property
    def serial_by_ref(self) -> dict[CfgBlockRef, int]:
        """Project the closed block rows into the source-ref index."""

        return {
            block.block_ref: block.serial
            for block in self.blocks
            if block.block_ref is not None
        }

    @property
    def physical_entry_reachable_serials(self) -> tuple[int, ...]:
        """Return the raw CFG successor closure rooted at ``entry_serial``.

        ``reachable_serials`` intentionally also includes typed semantic-site
        roots, so effects and route endpoints behind an indirect dispatcher
        remain available to the authority inventory.  Delivery obligations,
        however, must not mistake that evidence-model closure for a physical
        path from the source entry.
        """

        if not self.blocks:
            return ()
        blocks_by_serial = {block.serial: block for block in self.blocks}
        reachable: set[int] = set()
        pending = [self.entry_serial]
        while pending:
            serial = pending.pop()
            if serial in reachable:
                continue
            block = blocks_by_serial.get(serial)
            if block is None:
                raise ValueError(
                    "physical entry successor is absent from inventory blocks"
                )
            reachable.add(serial)
            pending.extend(reversed(block.successor_serials))
        return tuple(sorted(reachable))

    @property
    def recognized_terminal_serials(self) -> frozenset[int]:
        """Return the graph-checks-compatible terminal block subset."""

        recognized: set[int] = set()
        for block in self.blocks:
            if block.serial not in self.reachable_serials:
                continue
            if block.block_kind is BlockKind.STOP:
                recognized.add(block.serial)
                continue
            if block.graph_start_ea == _BADADDR and not block.successor_serials:
                recognized.add(block.serial)
                continue
            if block.instruction_observations and block.instruction_observations[-1].instruction_kind is InsnKind.RET:
                recognized.add(block.serial)
        return frozenset(recognized)

    def __post_init__(self) -> None:
        if type(self.phase) is not UnflattenAuthorityPhase:
            raise TypeError("phase must be UnflattenAuthorityPhase")
        occurrences = self.observed_route_topology_occurrences
        if type(occurrences) is not tuple or any(
            type(item) is not ObservedRouteTopologyOccurrence
            for item in occurrences
        ):
            raise TypeError(
                "observed_route_topology_occurrences must be an exact tuple",
            )
        if occurrences and self.phase is not UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
            raise ValueError(
                "observed route topology occurrences require observed phase",
            )
        if tuple(item.occurrence_id for item in occurrences) != tuple(
            sorted(item.occurrence_id for item in occurrences)
        ) or len({item.occurrence_id for item in occurrences}) != len(occurrences):
            raise ValueError("observed route topology occurrences must be canonical")
        for occurrence in occurrences:
            occurrence.__post_init__()
        conditional_occurrences = (
            self.observed_lowered_conditional_topology_occurrences
        )
        if type(conditional_occurrences) is not tuple or any(
            type(item) is not ObservedLoweredConditionalTopologyOccurrence
            for item in conditional_occurrences
        ):
            raise TypeError(
                "observed_lowered_conditional_topology_occurrences must be an exact tuple",
            )
        if (
            conditional_occurrences
            and self.phase is not UnflattenAuthorityPhase.OBSERVED_POST_APPLY
        ):
            raise ValueError(
                "observed lowered conditional occurrences require observed phase",
            )
        if tuple(item.occurrence_id for item in conditional_occurrences) != tuple(
            sorted(item.occurrence_id for item in conditional_occurrences)
        ) or len({item.occurrence_id for item in conditional_occurrences}) != len(
            conditional_occurrences
        ):
            raise ValueError(
                "observed lowered conditional occurrences must be canonical",
            )
        for occurrence in conditional_occurrences:
            occurrence.__post_init__()
        if type(self.graph_fingerprint) is not str:
            raise TypeError("graph_fingerprint must be an exact string")
        _id(self.graph_fingerprint, "graph_fingerprint")
        _inventory_nonnegative(self.generation, "generation")
        _inventory_ea(self.function_ea, "function_ea")
        _inventory_nonnegative(self.entry_serial, "entry_serial")
        for name, cls in (
            ("blocks", InventoryBlockObservation),
            ("subjects", SemanticSubjectRef),
            ("bindings", PhaseSubjectBinding),
            ("effects", InventoryEffectSite),
            ("terminals", InventoryTerminalSite),
            ("topology", InventoryTopologyIncidence),
        ):
            values = getattr(self, name)
            if type(values) is not tuple:
                raise TypeError(f"{name} must be an exact tuple")
            if any(type(value) is not cls for value in values):
                raise TypeError(f"{name} contains a non-nominal record")
            for value in values:
                _validate_inventory_refs(
                    value,
                    producer=self.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST,
                    label=name,
                )
            for value in values:
                value.__post_init__()
            object.__setattr__(self, name, values)
        if tuple(item.serial for item in self.blocks) != tuple(sorted(item.serial for item in self.blocks)):
            raise ValueError("blocks must be in canonical serial order")
        if len({item.serial for item in self.blocks}) != len(self.blocks):
            raise ValueError("blocks must have unique serials")
        reachable_serials = self.reachable_serials
        if type(reachable_serials) is not tuple:
            raise TypeError("reachable_serials must be an exact tuple")
        if any(type(serial) is not int or serial < 0 for serial in reachable_serials):
            raise TypeError("reachable_serials must contain exact non-negative ints")
        if reachable_serials != tuple(sorted(set(reachable_serials))):
            raise ValueError("reachable_serials must be sorted and unique")
        block_serials = {item.serial for item in self.blocks}
        if self.blocks and self.entry_serial not in block_serials:
            raise ValueError("entry_serial must refer to an inventory block")
        if not self.blocks and self.entry_serial != 0:
            raise ValueError("empty inventories require entry_serial 0")
        if not set(reachable_serials) <= block_serials:
            raise ValueError("reachable_serials must refer to inventory blocks")
        if self.blocks and not reachable_serials:
            raise ValueError("reachable_serials must be nonempty when blocks exist")
        expected_reachable: set[int] = set()
        if self.blocks:
            blocks_by_serial = {item.serial: item for item in self.blocks}
            serial_by_ref = {
                item.block_ref: item.serial
                for item in self.blocks
                if item.block_ref is not None
            }
            dispatcher_serials = {
                serial_by_ref.get(subject.block_ref)
                for subject in self.subjects
                if subject.role is SemanticSubjectRole.DISPATCHER_ENTRY
            }
            if len(dispatcher_serials) > 1 or None in dispatcher_serials:
                raise ValueError(
                    "semantic inventory dispatcher entry is ambiguous or unbound"
                )
            dispatcher_serial = (
                next(iter(dispatcher_serials)) if dispatcher_serials else None
            )
            component_refs = {
                subject.block_ref
                for subject in self.subjects
                if subject.role
                is SemanticSubjectRole.DETACHED_DEAD_HANDLER_COMPONENT
            }
            authoritative_handler_refs = {
                subject.block_ref
                for subject in self.subjects
                if subject.role is SemanticSubjectRole.AUTHORITATIVE_HANDLER
            }
            candidate_detached_handler_refs = (
                component_refs & authoritative_handler_refs
                if self.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST
                else set()
            )
            candidate_exact_effect_refs = (
                {
                    subject.block_ref
                    for subject in self.subjects
                    if subject.role
                    is SemanticSubjectRole.EXACT_EFFECT_DISCARDED_OWNER
                }
                if self.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST
                else set()
            )
            candidate_default_gap_refs = (
                {
                    subject.block_ref
                    for subject in self.subjects
                    if subject.role
                    is SemanticSubjectRole.DEFAULT_GAP_INFEASIBLE_RESIDUAL
                }
                if self.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST
                else set()
            )
            candidate_semantic_loss_refs = (
                candidate_detached_handler_refs
                | candidate_exact_effect_refs
                | candidate_default_gap_refs
            )
            semantic_roots: set[int] = set()
            for subject in self.subjects:
                # Candidate semantic-loss subjects are the typed markers that
                # permit their source handler/route aliases to be tested as
                # absent. Rooting a detached handler or exact-infeasible
                # effect owner here would pre-accept the opposite topology
                # before the transaction-owned binder can decide it.
                if subject.block_ref in candidate_semantic_loss_refs:
                    continue
                if (
                    (
                        subject.role is SemanticSubjectRole.AUTHORITATIVE_HANDLER
                        and type(subject.locator) is HandlerSubjectLocator
                    )
                    or (
                        subject.role in {
                            SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                            SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
                        }
                        and type(subject.locator) is BlockSubjectLocator
                    )
                ):
                    serial = serial_by_ref.get(subject.block_ref)
                    if serial is None:
                        if self.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST:
                            raise ValueError(
                                "semantic root subject is absent from source inventory blocks"
                            )
                        continue
                    semantic_roots.add(serial)
            # Physical entry reachability remains ordinary CFG reachability.
            # Typed handler/route roots are an evidence-model supplement and
            # stop before dispatcher infrastructure so they cannot make a
            # retired dispatcher semantically reachable by construction.
            pending = [self.entry_serial]
            while pending:
                serial = pending.pop()
                if serial in expected_reachable:
                    continue
                block = blocks_by_serial.get(serial)
                if block is None:
                    raise ValueError("reachable successor is absent from inventory blocks")
                expected_reachable.add(serial)
                pending.extend(reversed(block.successor_serials))
            pending = list(sorted(semantic_roots, reverse=True))
            while pending:
                serial = pending.pop()
                barrier_active = (
                    self.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST
                    and dispatcher_serial is not None
                )
                if (
                    barrier_active and serial == dispatcher_serial
                    or serial in expected_reachable
                ):
                    continue
                block = blocks_by_serial.get(serial)
                if block is None:
                    raise ValueError(
                        "semantic root successor is absent from inventory blocks"
                    )
                expected_reachable.add(serial)
                pending.extend(
                    successor
                    for successor in reversed(block.successor_serials)
                    if not barrier_active or successor != dispatcher_serial
                )
        if tuple(sorted(expected_reachable)) != reachable_serials:
            raise ValueError(
                "reachable_serials must equal the semantic-root successor closure"
            )
        source_subject_ids = self.source_subject_ids
        if type(source_subject_ids) is not tuple:
            raise TypeError("source_subject_ids must be an exact tuple")
        if any(type(item) is not str for item in source_subject_ids):
            raise TypeError("source_subject_ids must contain exact strings")
        if source_subject_ids != tuple(sorted(set(source_subject_ids))):
            raise ValueError("source_subject_ids must be sorted and unique")
        if tuple(item.subject_id for item in self.subjects) != tuple(sorted(item.subject_id for item in self.subjects)):
            raise ValueError("subjects must be in canonical subject-id order")
        if len({item.subject_id for item in self.subjects}) != len(self.subjects):
            raise ValueError("subjects must have unique subject IDs")
        if tuple(item.subject.subject_id for item in self.bindings) != tuple(sorted(item.subject.subject_id for item in self.bindings)):
            raise ValueError("bindings must be in canonical subject-id order")
        if len({item.subject.subject_id for item in self.bindings}) != len(self.bindings):
            raise ValueError("bindings must have unique subject IDs")
        subjects_by_id = {item.subject_id: item for item in self.subjects}
        for binding in self.bindings:
            canonical_subject = subjects_by_id.get(binding.subject.subject_id)
            if canonical_subject is None:
                raise ValueError("binding subject is absent from subjects")
            if (
                binding.subject != canonical_subject
                or canonical_bytes(binding.subject) != canonical_bytes(canonical_subject)
            ):
                raise ValueError("binding subject does not match canonical subject content")
        effects = tuple(sorted(self.effects, key=lambda item: (item.owner_serial, item.instruction_ordinal, item.instruction_ea, item.effect_kind.value)))
        terminals = tuple(sorted(self.terminals, key=lambda item: (item.owner_serial, item.instruction_ordinal is None, item.instruction_ordinal if item.instruction_ordinal is not None else -1, item.instruction_ea, item.terminal_kind.value)))
        topology = tuple(sorted(self.topology, key=lambda item: (item.kind.value, item.owner_serial, item.peer_serial, item.source_transfer_ea if item.source_transfer_ea is not None else -1)))
        if effects != self.effects or terminals != self.terminals or topology != self.topology:
            raise ValueError("inventory rows must be in canonical order")
        if len({(item.owner_serial, item.instruction_ea, item.effect_kind) for item in self.effects}) != len(self.effects):
            raise ValueError("effects must have unique site keys")
        if len({(item.owner_serial, item.instruction_ea, item.terminal_kind) for item in self.terminals}) != len(self.terminals):
            raise ValueError("terminals must have unique site keys")
        mapped_block_refs = tuple(
            item.block_ref for item in self.blocks if item.block_ref is not None
        )
        if len(set(mapped_block_refs)) != len(mapped_block_refs):
            raise ValueError("duplicate block reference in inventory rows")
        blocks = {item.serial: item for item in self.blocks}
        serial_by_ref = {
            item.block_ref: item.serial
            for item in self.blocks
            if item.block_ref is not None
        }
        if self.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST and any(
            (item.block_ref is None or item.anchor_ea is None)
            and not _is_unowned_structural_stop_row(item)
            and not _is_exact_logical_function_exit_row(item)
            for item in self.blocks
        ):
            raise ValueError("producer observations require mapped block identities and anchors")
        if self.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST:
            for item in self.blocks:
                if (
                    _is_unowned_structural_stop_row(item)
                    or _is_exact_logical_function_exit_row(item)
                ):
                    continue
                if (
                    item.anchor_ea is None
                    or not _anchor_matches_native_scope(
                        item.block_ref, item.anchor_ea,
                        item.native_instruction_eas,
                    )
                ):
                    raise ValueError(
                        "producer anchors must belong to native scope"
                    )
        for block in self.blocks:
            if type(block.block_ref) is NativeBlockRef:
                identity = block.block_ref.identity
                phase_anchor_preserving_subset = (
                    self.phase in {
                        UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                        UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
                    }
                    and _phase_native_origin_subset_preserves_anchor(
                        block.block_ref,
                        block.anchor_ea,
                        block.native_instruction_eas,
                        tuple(sorted(identity.exact_instruction_eas)),
                    )
                )
                if (
                    identity.exact_instruction_eas
                    != frozenset(block.native_instruction_eas)
                    and not phase_anchor_preserving_subset
                ):
                    expected_instruction_eas = set(identity.exact_instruction_eas)
                    observed_instruction_eas = set(block.native_instruction_eas)
                    anchor = (
                        "unknown" if block.anchor_ea is None
                        else f"0x{block.anchor_ea:x}"
                    )
                    raise ValueError(
                        "native identity instruction EAs do not match block row: "
                        f"blk{block.serial}@{anchor} "
                        f"unexpected={tuple(sorted(observed_instruction_eas - expected_instruction_eas))} "
                        f"missing={tuple(sorted(expected_instruction_eas - observed_instruction_eas))}"
                    )
                if block.anchor_ea is None or not identity.native_ranges.contains(block.anchor_ea):
                    raise ValueError("native identity ranges do not contain block anchor")
        subject_ids = {item.subject_id for item in self.subjects}
        if not set(source_subject_ids) <= subject_ids:
            raise ValueError("source_subject_ids must refer to inventory subjects")
        if self.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST and set(source_subject_ids) != subject_ids:
            raise ValueError("producer source subject partition must cover all subjects")
        if {item.subject.subject_id for item in self.bindings} != subject_ids:
            raise ValueError("inventory bindings must cover subjects exactly")
        for binding in self.bindings:
            if binding.subject.subject_id not in subject_ids:
                raise ValueError("binding subject is absent from subjects")
            if binding.phase is not self.phase:
                raise ValueError("binding phase does not match inventory phase")
            if binding.graph_fingerprint != self.graph_fingerprint or binding.generation != self.generation:
                raise ValueError("binding graph authority does not match inventory")
            if binding.status is SubjectBindingStatus.UNIQUE:
                block = blocks.get(binding.serial)
                if block is None:
                    raise ValueError("unique binding serial is absent from blocks")
                route_endpoint_binding = (
                    binding.role in {
                        SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                        SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
                    }
                    and type(binding.block_ref) is NativeBlockRef
                    and binding.anchor_ea is not None
                    and binding.block_ref.identity.native_ranges.contains(
                        binding.anchor_ea,
                    )
                )
                if (
                    binding.block_ref != block.block_ref
                    or binding.native_instruction_eas != block.native_instruction_eas
                    or (
                        not route_endpoint_binding
                        and binding.anchor_ea != block.anchor_ea
                    )
                ):
                    raise ValueError("unique binding does not match its block observation")
                occurrence = binding.observed_logical_occurrence
                if occurrence is not None:
                    if not _is_exact_logical_function_exit_row(block):
                        raise ValueError(
                            "observed logical occurrence does not bind an exact exit row"
                        )
                    predecessor_refs = tuple(
                        blocks[serial].block_ref
                        for serial in block.predecessor_serials
                    )
                    if (
                        any(ref is None for ref in predecessor_refs)
                        or set(predecessor_refs) != set(occurrence.predecessor_refs)
                    ):
                        raise ValueError(
                            "observed logical occurrence predecessor identity drifted"
                        )
                    reverse_predecessors = {
                        row.serial
                        for row in self.blocks
                        if block.serial in row.successor_serials
                    }
                    if set(block.predecessor_serials) != reverse_predecessors:
                        raise ValueError(
                            "observed logical occurrence predecessor topology is incomplete"
                        )
                    owner_serial = serial_by_ref.get(occurrence.owner_ref)
                    owner = blocks.get(owner_serial)
                    if (
                        owner is None
                        or owner.block_kind is not BlockKind.ONE_WAY
                        or owner.successor_serials != (block.serial,)
                        or not owner.instruction_observations
                    ):
                        raise ValueError(
                            "observed logical occurrence plan owner is not an exact GOTO"
                        )
                    tail = owner.instruction_observations[-1]
                    if (
                        tail.instruction_kind is not InsnKind.GOTO
                        or tail.control_transfer_kind
                        is not ControlTransferKind.GOTO
                        or tail.is_call
                        or tail.call_kind is not None
                        or tail.predicate_observation is not None
                    ):
                        raise ValueError(
                            "observed logical occurrence owner tail is not an exact GOTO"
                        )
        for binding in self.bindings:
            if binding.subject.role in (
                SemanticSubjectRole.EFFECT_SITE,
                SemanticSubjectRole.TERMINAL_SITE,
            ) and type(binding.subject.locator) in (
                EffectSubjectLocator,
                TerminalSubjectLocator,
            ):
                expected_binding = resolve_inventory_site_binding(
                    binding.subject,
                    binding,
                    effects=tuple(
                        row for row in self.effects
                        if row.owner_serial in self.reachable_serials
                    ),
                    terminals=tuple(
                        row for row in self.terminals
                        if row.owner_serial in self.reachable_serials
                    ),
                    reachable_serials=self.reachable_serials,
                    serial_by_ref=serial_by_ref,
                )
                if binding != expected_binding:
                    raise ValueError("site binding disagrees with exact inventory resolver")
        resolved_effects_by_serial: dict[int, tuple[InventoryEffectSite, ...]] = {}
        resolved_terminals_by_serial: dict[int, tuple[InventoryTerminalSite, ...]] = {}
        for block in self.blocks:
            resolved_effects_by_serial[block.serial], resolved_terminals_by_serial[block.serial] = resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea if block.anchor_ea is not None else 0,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )
        for item in (*self.effects, *self.terminals):
            block = blocks.get(item.owner_serial)
            if block is None:
                raise ValueError("inventory site owner is absent from blocks")
            if item.owner_ref != block.block_ref or item.owner_anchor_ea != block.anchor_ea:
                raise ValueError("inventory site owner does not match block row")
            derived = (
                resolved_effects_by_serial[item.owner_serial]
                if isinstance(item, InventoryEffectSite)
                else resolved_terminals_by_serial[item.owner_serial]
            )
            if item not in derived:
                raise ValueError("inventory site disagrees with raw instruction resolver")
        expected_effect_keys = {
            (item.owner_serial, item.instruction_ea, item.effect_kind)
            for values in resolved_effects_by_serial.values()
            for item in values
        }
        actual_effect_keys = {
            (item.owner_serial, item.instruction_ea, item.effect_kind) for item in self.effects
        }
        if expected_effect_keys != actual_effect_keys:
            raise ValueError("inventory effects are incomplete or contain foreign rows")
        expected_terminal_keys = {
            (item.owner_serial, item.instruction_ea, item.terminal_kind)
            for values in resolved_terminals_by_serial.values()
            for item in values
        }
        for block in self.blocks:
            if block.block_kind is not BlockKind.STOP and any(
                item.owner_serial == block.serial and item.terminal_kind is TerminalKind.STOP
                for item in self.terminals
            ):
                raise ValueError("STOP terminal requires a STOP block")
        actual_terminal_keys = {
            (item.owner_serial, item.instruction_ea, item.terminal_kind) for item in self.terminals
        }
        if expected_terminal_keys != actual_terminal_keys:
            raise ValueError("inventory terminals are incomplete or contain foreign rows")
        source_subject_set = set(source_subject_ids)
        reachable_effect_keys = {
            (item.owner_ref, item.owner_anchor_ea, item.instruction_ea, item.effect_kind)
            for item in self.effects
            if item.owner_serial in self.reachable_serials
        }
        reachable_terminal_keys = {
            (item.owner_ref, item.owner_anchor_ea, item.instruction_ea, item.terminal_kind)
            for item in self.terminals
            if item.owner_serial in self.reachable_serials
        }
        all_effect_subject_keys = {
            (
                item.locator.owner_ref,
                item.locator.owner_anchor_ea,
                item.locator.instruction_ea,
                item.locator.effect_kind,
            )
            for item in self.subjects
            if item.role is SemanticSubjectRole.EFFECT_SITE
            and type(item.locator) is EffectSubjectLocator
        }
        all_terminal_subject_keys = {
            (
                item.locator.block_ref,
                item.locator.anchor_ea,
                item.locator.instruction_ea,
                item.locator.terminal_kind,
            )
            for item in self.subjects
            if item.role is SemanticSubjectRole.TERMINAL_SITE
            and type(item.locator) is TerminalSubjectLocator
        }
        effect_subject_keys = {
            key for item, key in (
                (
                    item,
                    (
                        item.locator.owner_ref,
                        item.locator.owner_anchor_ea,
                        item.locator.instruction_ea,
                        item.locator.effect_kind,
                    ),
                )
                for item in self.subjects
                if item.role is SemanticSubjectRole.EFFECT_SITE
                and type(item.locator) is EffectSubjectLocator
            )
            if item.subject_id not in source_subject_set
        }
        terminal_subject_keys = {
            key for item, key in (
                (
                    item,
                    (
                        item.locator.block_ref,
                        item.locator.anchor_ea,
                        item.locator.instruction_ea,
                        item.locator.terminal_kind,
                    ),
                )
                for item in self.subjects
                if item.role is SemanticSubjectRole.TERMINAL_SITE
                and type(item.locator) is TerminalSubjectLocator
            )
            if item.subject_id not in source_subject_set
        }
        if self.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST:
            if all_effect_subject_keys != reachable_effect_keys:
                raise ValueError("producer effect subjects must equal reachable raw effects")
            if all_terminal_subject_keys != reachable_terminal_keys:
                raise ValueError("producer terminal subjects must equal reachable raw terminals")
        if not effect_subject_keys <= reachable_effect_keys:
            raise ValueError("candidate effect subjects must own reachable raw effects")
        if not terminal_subject_keys <= reachable_terminal_keys:
            raise ValueError("candidate terminal subjects must own reachable raw terminals")
        if self.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST and self.subjects:
            expected_candidate_effects = reachable_effect_keys - {
                (
                    item.locator.owner_ref,
                    item.locator.owner_anchor_ea,
                    item.locator.instruction_ea,
                    item.locator.effect_kind,
                )
                for item in self.subjects
                if item.role is SemanticSubjectRole.EFFECT_SITE
                and type(item.locator) is EffectSubjectLocator
                and item.subject_id in source_subject_set
            }
            if expected_candidate_effects - effect_subject_keys:
                raise ValueError("candidate reachable effects are missing subjects")
            expected_candidate_terminals = reachable_terminal_keys - {
                (
                    item.locator.block_ref,
                    item.locator.anchor_ea,
                    item.locator.instruction_ea,
                    item.locator.terminal_kind,
                )
                for item in self.subjects
                if item.role is SemanticSubjectRole.TERMINAL_SITE
                and type(item.locator) is TerminalSubjectLocator
                and item.subject_id in source_subject_set
            }
            if expected_candidate_terminals - terminal_subject_keys:
                raise ValueError("candidate reachable terminals are missing subjects")
        for block in self.blocks:
            if block.transfer_ea is not None and block.transfer_ea not in block.native_instruction_eas:
                raise ValueError("block transfer EA is outside instruction rows")
        for item in self.topology:
            if item.owner_serial not in blocks:
                raise ValueError("topology incidence owner is absent from blocks")
            owner = blocks[item.owner_serial]
            if item.kind is TopologyIncidenceKind.SUCCESSOR:
                if item.source_transfer_ea != owner.transfer_ea:
                    raise ValueError("successor transfer does not match owner block")
            else:
                peer = blocks.get(item.peer_serial)
                if item.source_transfer_ea != (peer.transfer_ea if peer is not None else None):
                    raise ValueError("predecessor transfer does not match peer block")
        topology_keys = {(item.kind, item.owner_serial, item.peer_serial) for item in self.topology}
        if len(topology_keys) != len(self.topology):
            raise ValueError("topology incidence must be unique")
        expected_topology = {
            (TopologyIncidenceKind.PREDECESSOR, block.serial, peer)
            for block in self.blocks for peer in block.predecessor_serials
        } | {
            (TopologyIncidenceKind.SUCCESSOR, block.serial, peer)
            for block in self.blocks for peer in block.successor_serials
        }
        if topology_keys != expected_topology:
            raise ValueError("topology incidence does not match block topology")
        # Check the digest last.  All semantic invariants, including replay of
        # typed site bindings, must be checked against the live rows before a
        # self-consistent (but forged) digest can make the inventory appear
        # valid.
        if type(self.inventory_digest) is not str:
            raise TypeError("inventory_digest must be an exact string")
        _id(self.inventory_digest, "inventory_digest")
        expected = semantic_graph_inventory_digest(
            self.phase, self.graph_fingerprint, self.generation, self.blocks,
            self.subjects, self.bindings, self.effects, self.terminals, self.topology,
            self.reachable_serials,
            self.entry_serial, self.source_subject_ids, self.function_ea,
            self.observed_route_topology_occurrences,
            self.observed_lowered_conditional_topology_occurrences,
        )
        if self.inventory_digest != expected:
            raise ValueError("inventory_digest does not match inventory content")
        session = active_canonical_session()
        if session is not None:
            session.seal_inventory(self, _occurrence_stamp(self))
            record_inventory_seal_mint()


def validate_semantic_graph_inventory(value: object) -> SemanticGraphInventory:
    """Revalidate a live inventory object before every authority consumption."""

    if type(value) is not SemanticGraphInventory:
        raise TypeError("inventory must be SemanticGraphInventory")
    session = active_canonical_session()
    if session is not None:
        sealed = session.inventory_is_sealed(value, _occurrence_stamp(value))
        record_inventory_seal_check(sealed)
        if sealed:
            return value
    value.__post_init__()
    return value


def _validate_terminal_cycle_phase_result_inventories(
    result: TerminalCyclePhaseResult,
    claim: TerminalCycleBreakClaim,
    source_inventory: SemanticGraphInventory,
    candidate_inventory: SemanticGraphInventory,
) -> None:
    """Replay one terminal-cycle result against the exact immutable graphs."""

    validate_semantic_graph_inventory(source_inventory)
    validate_semantic_graph_inventory(candidate_inventory)
    cycle = claim.cycle_subject.locator
    terminal = claim.terminal_subject.locator
    if (
        type(cycle) is not CorridorSubjectLocator
        or type(terminal) not in (
            TerminalSubjectLocator,
            LogicalFunctionExitSubjectLocator,
        )
    ):
        raise ValueError("terminal-cycle inventory replay requires closed locators")

    def exact_binding(
        bindings: tuple[PhaseSubjectBinding, ...],
        *,
        subject_id: str | None = None,
        block_ref: NativeBlockRef | LogicalBlockRef | None = None,
        role: SemanticSubjectRole | None = None,
    ) -> PhaseSubjectBinding:
        rows = tuple(
            binding for binding in bindings
            if (subject_id is None or binding.subject.subject_id == subject_id)
            and (block_ref is None or binding.subject.block_ref == block_ref)
            and (role is None or binding.subject.role is role)
        )
        if (
            len(rows) != 1
            or rows[0].status is not SubjectBindingStatus.UNIQUE
            or rows[0].serial is None
        ):
            raise ValueError(
                "terminal-cycle inventory relation lacks one exact binding"
            )
        return rows[0]

    def residue_edges(
        inventory: SemanticGraphInventory,
        bindings: tuple[PhaseSubjectBinding, ...],
    ) -> tuple[tuple[NativeBlockRef | LogicalBlockRef, NativeBlockRef | LogicalBlockRef], ...]:
        ref_by_serial = {
            exact_binding(
                bindings,
                block_ref=ref,
                role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            ).serial: ref
            for ref in result.residue_refs
        }
        edges = {
            (ref_by_serial[row.owner_serial], ref_by_serial[row.peer_serial])
            for row in inventory.topology
            if row.kind is TopologyIncidenceKind.SUCCESSOR
            and row.owner_serial in ref_by_serial
            and row.peer_serial in ref_by_serial
        }
        return tuple(sorted(
            edges,
            key=lambda edge: (_structural_key(edge[0]), _structural_key(edge[1])),
        ))

    replayed_source_edges = residue_edges(
        source_inventory, result.source_bindings,
    )
    replayed_candidate_edges = residue_edges(
        candidate_inventory, result.candidate_bindings,
    )
    if (
        replayed_source_edges != result.source_cycle_edges
        or replayed_candidate_edges != result.candidate_cycle_edges
    ):
        raise ValueError(
            "terminal-cycle phase result residue topology differs from inventories"
        )
    source_entry = exact_binding(
        result.source_bindings,
        block_ref=cycle.entry_ref,
        role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
    )
    if source_entry.serial not in set(source_inventory.reachable_serials):
        raise ValueError("terminal-cycle source residue is not source-reachable")

    route_source = exact_binding(
        result.candidate_bindings,
        block_ref=result.terminal_source_ref,
        role=SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
    )
    cleanup = exact_binding(
        result.candidate_bindings,
        subject_id=claim.cleanup_source_subject.subject_id,
    )
    carrier = exact_binding(
        result.candidate_bindings,
        block_ref=result.terminal_carrier_ref,
        role=SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
    )
    terminal_binding = exact_binding(
        result.candidate_bindings,
        subject_id=claim.terminal_subject.subject_id,
    )
    candidate_blocks = {
        block.serial: block for block in candidate_inventory.blocks
    }
    if (
        tuple(candidate_blocks[route_source.serial].successor_serials)
        != (carrier.serial,)
        or tuple(candidate_blocks[cleanup.serial].successor_serials)
        != (carrier.serial,)
    ):
        raise ValueError(
            "terminal-cycle redirect topology differs from the phase result"
        )

    reachable = set(candidate_inventory.reachable_serials)
    if (
        route_source.serial not in reachable
        or carrier.serial not in reachable
        or terminal_binding.serial not in reachable
    ):
        raise ValueError("terminal-cycle terminal route is not candidate-reachable")
    serial = carrier.serial
    seen: set[int] = set()
    route_refs: list[NativeBlockRef | LogicalBlockRef] = []
    while serial not in seen:
        seen.add(serial)
        block = candidate_blocks.get(serial)
        if block is None or type(block.block_ref) not in (
            NativeBlockRef, LogicalBlockRef,
        ):
            raise ValueError("terminal-cycle route contains an unbound block")
        route_refs.append(block.block_ref)
        successors = tuple(
            successor for successor in block.successor_serials
            if successor in reachable
        )
        if serial == terminal_binding.serial:
            if successors:
                raise ValueError(
                    "terminal-cycle route endpoint has a live successor"
                )
            break
        if len(successors) != 1:
            raise ValueError("terminal-cycle route is not one exact corridor")
        serial = successors[0]
    else:
        raise ValueError("terminal-cycle terminal route contains a cycle")
    if tuple(route_refs) != result.terminal_route_refs:
        raise ValueError(
            "terminal-cycle terminal path differs from the phase result"
        )

    if type(terminal) is TerminalSubjectLocator:
        terminal_rows = tuple(
            row for row in candidate_inventory.terminals
            if row.owner_serial == terminal_binding.serial
            and row.owner_ref == terminal.block_ref
            and row.owner_anchor_ea == terminal.anchor_ea
            and row.terminal_kind is terminal.terminal_kind
            and row.instruction_ea == terminal.instruction_ea
        )
        if len(terminal_rows) != 1:
            raise ValueError(
                "terminal-cycle exact terminal site differs from the inventory"
            )


@dataclass(frozen=True, slots=True)
class PreparationBuildMetrics:
    source_inventory_builds: int
    candidate_inventory_builds: int
    inventory_ms: float

    def __post_init__(self) -> None:
        if type(self.source_inventory_builds) is not int or type(self.candidate_inventory_builds) is not int:
            raise TypeError("preparation inventory build counts must be exact ints")
        if self.source_inventory_builds != 1 or self.candidate_inventory_builds != 1:
            raise ValueError("preparation must build each inventory exactly once")
        if type(self.inventory_ms) not in (int, float) or isinstance(self.inventory_ms, bool):
            raise TypeError("inventory_ms must be a finite nonnegative number")
        if not math.isfinite(float(self.inventory_ms)) or self.inventory_ms < 0:
            raise ValueError("inventory_ms must be a finite nonnegative number")


def validate_preparation_build_metrics(value: object) -> PreparationBuildMetrics:
    """Revalidate projected receipt provenance before consumption."""

    if type(value) is not PreparationBuildMetrics:
        raise TypeError("preparation_metrics must be PreparationBuildMetrics")
    value.__post_init__()
    return value


@dataclass(frozen=True, slots=True)
class ConditionalSubjectRelation:
    source_subject_id: str
    target_subject_id: str
    dimension: SafetyDimension
    provenance_id: str

    def __post_init__(self) -> None:
        _id(self.source_subject_id, "source_subject_id")
        _id(self.target_subject_id, "target_subject_id")
        _enum(self.dimension, SafetyDimension, "dimension")
        _id(self.provenance_id, "provenance_id")


@dataclass(frozen=True, slots=True, init=False)
class PreparationAuthorityReceipt:
    receipt_id: str
    proposal_id: str
    plan_id: str
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    source_inventory_digest: str
    candidate_inventory_digest: str
    source_binding_digest: str
    candidate_binding_digest: str
    route_expansion_digest: str
    effect_catalog_digest: str
    terminal_catalog_digest: str
    plan_input_digest: str
    dispatcher_member_digest: str
    planned_helper_digest: str
    patch_step_digest: str
    conditional_relation_digest: str
    projected_topology_reference_digest: str
    metrics: PreparationBuildMetrics
    generic_gate_facts_digest: str | None = None
    source_route_authority_id: str | None = None
    projected_route_realization_id: str | None = None
    corridor_coverage_forecast: CorridorCoverageForecastAuthority | None = None
    retirement_candidate_catalog: RetirementCandidateCatalog | None = None
    # The receipt remains constructor-closed.  The transaction package uses
    # ``mint`` below after it has completed both inventory walks; callers
    # cannot provide either an ID or an authority token.
    _minted: bool = dataclass_field(init=False, repr=False, compare=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("preparation receipts are transaction-owned")

    def __post_init__(self) -> None:
        if getattr(self, "_minted", None) is not True:
            raise TypeError("preparation receipts are transaction-owned")
        for name in (
            "receipt_id", "proposal_id", "plan_id", "source_fingerprint",
            "candidate_fingerprint", "source_inventory_digest",
            "candidate_inventory_digest", "source_binding_digest",
            "candidate_binding_digest", "route_expansion_digest",
            "effect_catalog_digest", "terminal_catalog_digest",
            "plan_input_digest", "dispatcher_member_digest",
            "planned_helper_digest", "patch_step_digest",
            "conditional_relation_digest",
        ):
            _id(getattr(self, name), name)
        for name in ("generic_gate_facts_digest", "source_route_authority_id", "projected_route_realization_id"):
            value = getattr(self, name)
            if value is not None:
                _id(value, name)
        _id(
            self.projected_topology_reference_digest,
            "projected_topology_reference_digest",
        )
        if self.retirement_candidate_catalog is not None and type(self.retirement_candidate_catalog) is not RetirementCandidateCatalog:
            raise TypeError("retirement_candidate_catalog must be RetirementCandidateCatalog or None")
        if self.retirement_candidate_catalog is not None:
            self.retirement_candidate_catalog.__post_init__()
            if self.retirement_candidate_catalog.source_generation != self.source_generation:
                raise ValueError("receipt retirement candidate catalog generation differs from source")
        if self.corridor_coverage_forecast is not None:
            if type(self.corridor_coverage_forecast) not in (
                CorridorCoverageForecast, DefaultGapInfeasibilityForecast,
            ):
                raise TypeError("corridor_coverage_forecast must be a closed corridor forecast or None")
            self.corridor_coverage_forecast.__post_init__()
            forecast = corridor_base_forecast(self.corridor_coverage_forecast)
            if forecast.plan_id != self.plan_id:
                raise ValueError("receipt corridor forecast belongs to a foreign plan")
            if forecast.source_generation != self.source_generation:
                raise ValueError("receipt corridor forecast generation differs from source")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        if type(self.metrics) is not PreparationBuildMetrics:
            raise TypeError("metrics must be PreparationBuildMetrics")
        validate_preparation_build_metrics(self.metrics)
        if self.receipt_id != receipt_id(self):
            raise ValueError("receipt_id does not match canonical receipt content")

    @classmethod
    def mint(cls, **values: object) -> "PreparationAuthorityReceipt":
        """Create one receipt from the transaction-owned complete inputs.

        This is intentionally the only model-level construction hook.  The
        transaction facade is the sole production caller and supplies the
        complete digest set; ``receipt_id`` and the construction seal are
        computed here rather than accepted from a caller.
        """
        if "receipt_id" in values or "_minted" in values:
            raise TypeError("receipt ID and construction seal are not caller inputs")
        required = {
            name for name in (
                "proposal_id", "plan_id", "source_fingerprint",
                "candidate_fingerprint", "source_generation",
                "candidate_generation", "source_inventory_digest",
                "candidate_inventory_digest", "source_binding_digest",
                "candidate_binding_digest", "route_expansion_digest",
                "effect_catalog_digest", "terminal_catalog_digest",
                "plan_input_digest", "dispatcher_member_digest",
                "planned_helper_digest", "patch_step_digest",
                "conditional_relation_digest", "projected_topology_reference_digest", "metrics",
                "generic_gate_facts_digest", "source_route_authority_id", "projected_route_realization_id",
                "corridor_coverage_forecast", "retirement_candidate_catalog",
            )
        }
        for name in ("generic_gate_facts_digest", "source_route_authority_id", "projected_route_realization_id"):
            if name in values:
                if values[name] is not None:
                    _id(values[name], name)
            else:
                values[name] = None
        values.setdefault("corridor_coverage_forecast", None)
        values.setdefault("retirement_candidate_catalog", None)
        if set(values) != required:
            raise TypeError("mint requires the complete preparation receipt inputs")
        instance = cls.__new__(cls)
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        object.__setattr__(instance, "receipt_id", "sha256:" + "0" * 64)
        object.__setattr__(instance, "_minted", True)
        object.__setattr__(instance, "receipt_id", receipt_id(instance))
        cls.__post_init__(instance)
        return instance


@dataclass(frozen=True, slots=True)
class SemanticPhaseMetrics:
    preparation_metrics: PreparationBuildMetrics
    source_inventory_builds: int
    candidate_inventory_builds: int
    index_folds: int
    view_graph_traversals: int
    phase: UnflattenAuthorityPhase
    phase_build_metrics: PhaseBuildMetrics

    def __post_init__(self) -> None:
        if type(self.preparation_metrics) is not PreparationBuildMetrics:
            raise TypeError("preparation_metrics must be PreparationBuildMetrics")
        validate_preparation_build_metrics(self.preparation_metrics)
        if type(self.phase) is not UnflattenAuthorityPhase:
            raise TypeError("phase must be UnflattenAuthorityPhase")
        for name in (
            "source_inventory_builds", "candidate_inventory_builds",
            "index_folds", "view_graph_traversals",
        ):
            if type(getattr(self, name)) is not int:
                raise TypeError(f"{name} must be an exact int")
        expected = {
            UnflattenAuthorityPhase.PRODUCER_FORECAST: (1, 1),
            UnflattenAuthorityPhase.PROJECTED_PREFLIGHT: (1, 1),
            UnflattenAuthorityPhase.OBSERVED_POST_APPLY: (0, 1),
        }[self.phase]
        if (
            self.source_inventory_builds,
            self.candidate_inventory_builds,
            self.index_folds,
            self.view_graph_traversals,
        ) != (*expected, 1, 0):
            raise ValueError("evaluator metrics do not match the authority phase")
        if type(self.phase_build_metrics) is not PhaseBuildMetrics:
            raise TypeError("phase_build_metrics must be PhaseBuildMetrics")
        validate_phase_build_metrics(self.phase_build_metrics)
        if self.phase_build_metrics.phase is not self.phase:
            raise ValueError("phase build metrics phase does not match semantic phase")
        if (
            self.phase_build_metrics.source_inventory_builds,
            self.phase_build_metrics.candidate_inventory_builds,
        ) != (self.source_inventory_builds, self.candidate_inventory_builds):
            raise ValueError("phase build metrics counts do not match semantic phase")

    @property
    def build_metrics(self) -> PhaseBuildMetrics:
        return self.phase_build_metrics


def _validate_retirement_phase_result_inventory_bindings(
    result: RetirementPhaseResult,
    source_inventory: SemanticGraphInventory,
    candidate_inventory: SemanticGraphInventory,
) -> None:
    """Require every phase row to carry the exact inventory binding object."""

    source_bindings = {
        item.subject.subject_id: item for item in source_inventory.bindings
    }
    candidate_bindings = {
        item.subject.subject_id: item for item in candidate_inventory.bindings
    }
    for member in result.members:
        source = source_bindings.get(member.source_binding.subject.subject_id)
        candidate = candidate_bindings.get(member.candidate_binding.subject.subject_id)
        if (
            source is not member.source_binding
            or candidate is not member.candidate_binding
        ):
            raise ValueError(
                "retirement phase result bindings differ from inventories",
            )


@dataclass(frozen=True, slots=True)
class DerivedUnflattenPreparationInputs:
    proposal: ProposedUnflattenContract
    claims: tuple[UnflattenClaim, ...]
    preparation_receipt: PreparationAuthorityReceipt
    source_inventory: SemanticGraphInventory
    candidate_inventory: SemanticGraphInventory
    projected_topology_reference: SemanticGraphInventory
    source_route_authority: SourceBoundRouteAuthority | None
    projected_route_realization: ProjectedRouteRealization | None
    generic_gate_facts: GenericCfgGateFacts | None
    conditional_relations: tuple[ConditionalSubjectRelation, ...]
    patch_step_facts: tuple[PatchStepEvidencePayload, ...]
    preparation_metrics: PreparationBuildMetrics
    phase_build_metrics: PhaseBuildMetrics
    corridor_coverage_phase_result: CorridorCoveragePhaseResultAuthority | None = None
    detached_dead_handler_component_source_results: tuple[DetachedDeadHandlerComponentSourceResult, ...] = ()
    detached_dead_handler_component_phase_results: tuple[DetachedDeadHandlerComponentPhaseResult, ...] = ()
    terminal_cycle_phase_results: tuple[TerminalCyclePhaseResult, ...] = ()
    retirement_phase_result: RetirementPhaseResult | None = None

    def __post_init__(self) -> None:
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("proposal must be a ProposedUnflattenContract")
        if type(self.preparation_receipt) is not PreparationAuthorityReceipt:
            raise TypeError("preparation_receipt must be PreparationAuthorityReceipt")
        if type(self.claims) is not tuple:
            raise TypeError("claims must be an exact tuple")
        for claim in self.claims:
            if type(claim) not in (RetiredDispatcherInfrastructureClaim,
                                   DetachedDeadHandlerComponentClaim,
                                   EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim,
                                   LocalAliasEffectScalarizationClaim, TerminalCycleBreakClaim):
                raise TypeError("claims must contain closed UnflattenClaim values")
        for name in ("source_inventory", "candidate_inventory"):
            inventory = getattr(self, name)
            if type(inventory) is not SemanticGraphInventory:
                raise TypeError(f"{name} must be SemanticGraphInventory")
            validate_semantic_graph_inventory(inventory)
        reference = self.projected_topology_reference
        if type(reference) is not SemanticGraphInventory:
            raise TypeError("projected_topology_reference must be SemanticGraphInventory")
        validate_semantic_graph_inventory(reference)
        if reference.phase is not UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("projected topology reference must be projected preflight")
        if (
            reference.function_ea != self.source_inventory.function_ea
            or reference.function_ea != self.candidate_inventory.function_ea
        ):
            raise ValueError("projected topology reference function EA differs from inventory")
        if reference.source_subject_ids != self.source_inventory.source_subject_ids:
            raise ValueError("projected topology reference subject partition differs")
        phase = self.phase_build_metrics.phase
        if phase is UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            if reference != self.candidate_inventory:
                raise ValueError("projected phase must match its candidate inventory")
            if reference.generation != self.candidate_inventory.generation:
                raise ValueError("projected topology reference generation differs from candidate")
        forecast_authority = self.proposal.corridor_coverage_forecast
        forecast = (
            corridor_base_forecast(forecast_authority)
            if forecast_authority is not None else None
        )
        if forecast is not None and not (
            forecast.function_ea == self.source_inventory.function_ea
            and forecast.function_ea == self.candidate_inventory.function_ea
        ):
            raise ValueError("corridor forecast function EA is not sealed to both inventories")
        if self.candidate_inventory.source_subject_ids != self.source_inventory.source_subject_ids:
            raise ValueError(
                "candidate source subject partition must equal source inventory partition"
            )
        synthetic_route_pair = (
            self.source_route_authority is None
            and self.projected_route_realization is None
        )
        if not synthetic_route_pair:
            if type(self.source_route_authority) is not SourceBoundRouteAuthority:
                raise TypeError("source_route_authority must be SourceBoundRouteAuthority")
            if type(self.projected_route_realization) is not ProjectedRouteRealization:
                raise TypeError("projected_route_realization must be ProjectedRouteRealization")
            if self.projected_route_realization.source_authority is not self.source_route_authority:
                raise ValueError("projected realization must retain exact source authority")
        if self.generic_gate_facts is not None:
            if type(self.generic_gate_facts) is not GenericCfgGateFacts:
                raise TypeError("generic_gate_facts must be GenericCfgGateFacts or None")
            self.generic_gate_facts.__post_init__()
        relations = _tuple(self.conditional_relations, "conditional_relations", sort=True)
        if any(type(value) is not ConditionalSubjectRelation for value in relations):
            raise TypeError("conditional_relations must contain ConditionalSubjectRelation values")
        object.__setattr__(self, "conditional_relations", relations)
        patch_facts = _tuple(self.patch_step_facts, "patch_step_facts")
        if any(type(value) is not PatchStepEvidencePayload for value in patch_facts):
            raise TypeError("patch_step_facts must contain PatchStepEvidencePayload values")
        object.__setattr__(self, "patch_step_facts", patch_facts)
        if type(self.preparation_metrics) is not PreparationBuildMetrics:
            raise TypeError("preparation_metrics must be PreparationBuildMetrics")
        if type(self.phase_build_metrics) is not PhaseBuildMetrics:
            raise TypeError("phase_build_metrics must be PhaseBuildMetrics")
        if self.corridor_coverage_phase_result is not None:
            if type(self.corridor_coverage_phase_result) not in (
                CorridorCoveragePhaseResult, DefaultGapInfeasibilityPhaseResult,
            ):
                raise TypeError("corridor_coverage_phase_result must be a closed corridor phase result or None")
            if forecast_authority is None:
                raise ValueError("corridor phase result is foreign to the proposal forecast")
            forecast, result = _validate_corridor_authority_pair(
                forecast_authority, self.corridor_coverage_phase_result,
            )
            if result.phase is not self.phase_build_metrics.phase:
                raise ValueError("corridor phase result phase differs from inputs")
            if (
                result.source_fingerprint != self.source_inventory.graph_fingerprint
                or result.source_fingerprint != self.preparation_receipt.source_fingerprint
                or result.candidate_fingerprint != self.candidate_inventory.graph_fingerprint
                or result.candidate_fingerprint != self.preparation_receipt.candidate_fingerprint
                or result.source_generation != self.source_inventory.generation
                or result.source_generation != self.preparation_receipt.source_generation
                or result.candidate_generation != self.candidate_inventory.generation
                or result.candidate_generation != self.preparation_receipt.candidate_generation
                or forecast.source_generation != self.source_inventory.generation
                or forecast.source_native_key != self.proposal.source_identity_catalog.native_key
            ):
                raise ValueError("corridor phase result coordinates are not sealed to inventories and receipt")
        elif self.proposal.corridor_coverage_forecast is not None:
            raise ValueError("typed corridor forecast requires a bound phase result")
        source_results = _tuple(
            self.detached_dead_handler_component_source_results,
            "detached_dead_handler_component_source_results", sort=True,
        )
        if any(type(item) is not DetachedDeadHandlerComponentSourceResult for item in source_results):
            raise TypeError("detached source results must be closed")
        for item in source_results:
            item.__post_init__()
            if (
                item.source_fingerprint != self.source_inventory.graph_fingerprint
                or item.source_generation != self.source_inventory.generation
                or self.corridor_coverage_phase_result is None
                or item.corridor_forecast_id
                != corridor_base_phase_result(
                    self.corridor_coverage_phase_result,
                ).forecast_id
            ):
                raise ValueError("detached source result is not sealed to preparation authority")
            if (
                self.phase_build_metrics.phase
                is UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
                and item.corridor_coverage_result_id
                != corridor_base_phase_result(
                    self.corridor_coverage_phase_result,
                ).result_id
            ):
                raise ValueError(
                    "projected detached source result differs from its minting corridor result"
                )
        phase_results = _tuple(
            self.detached_dead_handler_component_phase_results,
            "detached_dead_handler_component_phase_results", sort=True,
        )
        if any(type(item) is not DetachedDeadHandlerComponentPhaseResult for item in phase_results):
            raise TypeError("detached phase results must be closed")
        by_claim = {item.claim_id: item for item in source_results}
        for item in phase_results:
            item.__post_init__()
            if item.accepted and by_claim.get(item.claim_id) is None:
                raise ValueError("accepted detached phase result lacks sealed source result")
            if item.accepted and item.source_result_id != by_claim[item.claim_id].result_id:
                raise ValueError("detached phase result source authority drifted")
        object.__setattr__(self, "detached_dead_handler_component_source_results", source_results)
        object.__setattr__(self, "detached_dead_handler_component_phase_results", phase_results)
        if self.retirement_phase_result is not None:
            result = self.retirement_phase_result
            if type(result) is not RetirementPhaseResult:
                raise TypeError("retirement_phase_result must be RetirementPhaseResult or None")
            result.__post_init__()
            catalog = self.proposal.retirement_candidate_catalog
            if catalog is None or result.catalog_id != catalog.catalog_id:
                raise ValueError("retirement phase result is foreign to proposal catalog")
            if set(item.block_ref for item in result.members) != set(catalog.member_refs):
                raise ValueError("retirement phase result is not exact plan coverage")
            if result.phase is not self.phase_build_metrics.phase:
                raise ValueError("retirement phase result phase differs from inputs")
            if result.source_fingerprint != self.source_inventory.graph_fingerprint or result.candidate_fingerprint != self.candidate_inventory.graph_fingerprint:
                raise ValueError("retirement phase result coordinates differ from inventories")
            candidate_ids = {
                item.block_ref: item.candidate_id
                for item in catalog.candidates
            }
            candidate_bindings = {
                item.subject.subject_id: item
                for item in self.candidate_inventory.bindings
            }
            _validate_retirement_phase_result_inventory_bindings(
                result, self.source_inventory, self.candidate_inventory,
            )
            from .bind import validate_retirement_phase_result
            validate_retirement_phase_result(result)
            for member in result.members:
                if member.candidate_id != candidate_ids.get(member.block_ref):
                    raise ValueError("retirement phase result candidate evidence drifted")
                candidate = candidate_bindings[member.candidate_binding.subject.subject_id]
                reachable = (
                    candidate.status is SubjectBindingStatus.UNIQUE
                    and candidate.serial in self.candidate_inventory.reachable_serials
                )
                if member.candidate_reachable is not None and member.candidate_reachable != reachable:
                    raise ValueError("retirement phase result reachability drifted from inventory")
        elif self.proposal.retirement_candidate_catalog is not None:
            raise ValueError("typed retirement candidate catalog requires a bound phase result")
        terminal_results = _validate_terminal_cycle_phase_results(
            self.terminal_cycle_phase_results,
            self.claims,
            phase=self.phase_build_metrics.phase,
            source_fingerprint=self.source_inventory.graph_fingerprint,
            candidate_fingerprint=self.candidate_inventory.graph_fingerprint,
            source_generation=self.source_inventory.generation,
            candidate_generation=self.candidate_inventory.generation,
            expected_source_bindings=self.source_inventory.bindings,
            expected_candidate_bindings=self.candidate_inventory.bindings,
            source_inventory=self.source_inventory,
            candidate_inventory=self.candidate_inventory,
        )
        object.__setattr__(self, "terminal_cycle_phase_results", terminal_results)
        has_retirement = any(
            type(claim) is RetiredDispatcherInfrastructureClaim for claim in self.claims
        )
        if has_retirement:
            if (
                self.proposal.retirement_candidate_catalog is None
                or self.preparation_receipt.retirement_candidate_catalog
                != self.proposal.retirement_candidate_catalog
            ):
                raise ValueError("retirement preparation records must share the candidate catalog")
        elif (
            self.proposal.retirement_candidate_catalog is not None
            or self.preparation_receipt.retirement_candidate_catalog is not None
        ):
            raise ValueError("retirement candidate catalog is present without a claim")
        if not _same_corridor_forecast_content(
            self.preparation_receipt.corridor_coverage_forecast,
            self.proposal.corridor_coverage_forecast,
        ):
            raise ValueError("preparation receipt corridor forecast differs from proposal")
        validate_preparation_build_metrics(self.preparation_metrics)
        validate_phase_build_metrics(self.phase_build_metrics)
        PreparationAuthorityReceipt.__post_init__(self.preparation_receipt)
        if self.source_inventory.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("source inventory must be producer forecast")
        if self.candidate_inventory.phase is not self.phase_build_metrics.phase:
            raise ValueError("candidate inventory phase does not match phase metrics")
        source_fingerprint = self.source_inventory.graph_fingerprint
        candidate_fingerprint = self.candidate_inventory.graph_fingerprint
        source_generation = self.source_inventory.generation
        candidate_generation = self.candidate_inventory.generation
        if not synthetic_route_pair:
            if (
                self.source_route_authority.proposal is not self.proposal
                or self.source_route_authority.source_fingerprint != source_fingerprint
                or self.source_route_authority.source_generation != source_generation
                or self.projected_route_realization.projected_fingerprint
                != self.projected_topology_reference.graph_fingerprint
                or self.projected_route_realization.projected_generation
                != self.projected_topology_reference.generation
            ):
                raise ValueError("route authority does not match preparation inventories")
            if self.preparation_receipt.source_route_authority_id != self.source_route_authority.source_authority_id:
                raise ValueError("receipt source authority ID does not match preparation")
            if self.preparation_receipt.projected_route_realization_id != self.projected_route_realization.realization_id:
                raise ValueError("receipt projected realization ID does not match preparation")
        elif (
            self.preparation_receipt.source_route_authority_id is not None
            or self.preparation_receipt.projected_route_realization_id is not None
        ):
            raise ValueError("synthetic inputs cannot carry route authority IDs")
        if self.preparation_receipt.source_inventory_digest != self.source_inventory.inventory_digest:
            raise ValueError("receipt source inventory digest does not match inventory")
        if self.preparation_receipt.candidate_inventory_digest != self.candidate_inventory.inventory_digest:
            raise ValueError("receipt candidate inventory digest does not match inventory")
        if self.preparation_receipt.projected_topology_reference_digest != reference.inventory_digest:
            raise ValueError("receipt projected topology reference digest does not match reference")


@dataclass(frozen=True, slots=True)
class SemanticSafetyCase:
    case_id: str
    authority_id: str
    preparation_receipt_id: str
    preparation_receipt: PreparationAuthorityReceipt
    phase: UnflattenAuthorityPhase
    source_fingerprint: str
    candidate_fingerprint: str
    candidate_generation: int
    claims: tuple[UnflattenClaim, ...]
    subjects: tuple[SemanticSubjectRef, ...]
    bindings: tuple[PhaseSubjectBinding, ...]
    conditional_relations: tuple[ConditionalSubjectRelation, ...]
    required_obligations: tuple[ObligationKey, ...]
    evidence: tuple[AuthorityEvidence, ...]
    justifications: tuple[AuthorityJustification, ...]
    obligation_index: ObligationEvidenceIndex
    phase_metrics: SemanticPhaseMetrics
    source_inventory: SemanticGraphInventory
    candidate_inventory: SemanticGraphInventory
    source_subject_ids: tuple[str, ...] = ()
    source_bindings: tuple[PhaseSubjectBinding, ...] = ()
    retirement_candidate_catalog: RetirementCandidateCatalog | None = None
    retirement_phase_result: RetirementPhaseResult | None = None
    corridor_coverage_phase_result: CorridorCoveragePhaseResultAuthority | None = None
    detached_dead_handler_component_source_results: tuple[DetachedDeadHandlerComponentSourceResult, ...] = ()
    detached_dead_handler_component_phase_results: tuple[DetachedDeadHandlerComponentPhaseResult, ...] = ()
    terminal_cycle_phase_results: tuple[TerminalCyclePhaseResult, ...] = ()

    def __post_init__(self) -> None:
        _id(self.case_id, "case_id")
        _id(self.authority_id, "authority_id")
        _id(self.preparation_receipt_id, "preparation_receipt_id")
        if type(self.preparation_receipt) is not PreparationAuthorityReceipt:
            raise TypeError("preparation_receipt must be PreparationAuthorityReceipt")
        PreparationAuthorityReceipt.__post_init__(self.preparation_receipt)
        validate_semantic_graph_inventory(self.source_inventory)
        validate_semantic_graph_inventory(self.candidate_inventory)
        forecast_authority = self.preparation_receipt.corridor_coverage_forecast
        forecast = (
            corridor_base_forecast(forecast_authority)
            if forecast_authority is not None else None
        )
        if forecast is not None and forecast.function_ea != self.source_inventory.function_ea:
            raise ValueError("case corridor forecast function EA differs from source inventory")
        if self.retirement_candidate_catalog is not None and type(self.retirement_candidate_catalog) is not RetirementCandidateCatalog:
            raise TypeError("retirement_candidate_catalog must be RetirementCandidateCatalog or None")
        if self.retirement_candidate_catalog is not None:
            self.retirement_candidate_catalog.__post_init__()
            if self.retirement_candidate_catalog.source_generation != self.preparation_receipt.source_generation:
                raise ValueError("retirement candidate catalog generation differs from receipt")
        elif self.preparation_receipt.retirement_candidate_catalog is not None:
            raise ValueError("receipt retirement candidate catalog requires a case catalog")
        if self.corridor_coverage_phase_result is not None:
            if type(self.corridor_coverage_phase_result) not in (
                CorridorCoveragePhaseResult, DefaultGapInfeasibilityPhaseResult,
            ):
                raise TypeError("corridor_coverage_phase_result must be a closed corridor phase result or None")
            if forecast_authority is None:
                raise ValueError("case corridor phase result is foreign to receipt forecast")
            forecast, result = _validate_corridor_authority_pair(
                forecast_authority, self.corridor_coverage_phase_result,
            )
            if (
                result.phase is not self.phase
                or result.source_fingerprint != self.source_fingerprint
                or result.candidate_fingerprint != self.candidate_fingerprint
                or result.source_fingerprint != self.source_inventory.graph_fingerprint
                or result.candidate_fingerprint != self.preparation_receipt.candidate_fingerprint
                or result.source_generation != self.preparation_receipt.source_generation
                or result.candidate_generation != self.candidate_generation
                or forecast.source_generation != self.preparation_receipt.source_generation
            ):
                raise ValueError("case corridor phase result coordinates are not sealed")
        elif self.preparation_receipt.corridor_coverage_forecast is not None:
            raise ValueError("typed corridor forecast requires a case-owned phase result")
        source_results = _tuple(
            self.detached_dead_handler_component_source_results,
            "detached_dead_handler_component_source_results", sort=True,
        )
        if any(type(item) is not DetachedDeadHandlerComponentSourceResult for item in source_results):
            raise TypeError("case detached source results must be closed")
        source_by_claim: dict[str, DetachedDeadHandlerComponentSourceResult] = {}
        from .bind import (
            validate_detached_phase_result,
            validate_detached_source_result,
        )
        for item in source_results:
            item.__post_init__()
            validate_detached_source_result(item)
            if item.claim_id in source_by_claim:
                raise ValueError("case detached source authority is ambiguous")
            if (
                item.source_fingerprint != self.source_inventory.graph_fingerprint
                or item.source_generation != self.source_inventory.generation
                or self.corridor_coverage_phase_result is None
                or item.corridor_forecast_id
                != corridor_base_phase_result(
                    self.corridor_coverage_phase_result,
                ).forecast_id
            ):
                raise ValueError("case detached source result has foreign coordinates")
            if (
                self.phase is UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
                and item.corridor_coverage_result_id
                != corridor_base_phase_result(
                    self.corridor_coverage_phase_result,
                ).result_id
            ):
                raise ValueError("case projected detached source result has foreign corridor authority")
            source_by_claim[item.claim_id] = item
        phase_results = _tuple(
            self.detached_dead_handler_component_phase_results,
            "detached_dead_handler_component_phase_results", sort=True,
        )
        if any(type(item) is not DetachedDeadHandlerComponentPhaseResult for item in phase_results):
            raise TypeError("case detached phase results must be closed")
        for item in phase_results:
            item.__post_init__()
            validate_detached_phase_result(item)
            source_result = source_by_claim.get(item.claim_id)
            if item.accepted and (
                source_result is None
                or item.source_result_id != source_result.result_id
            ):
                raise ValueError("case detached phase result lacks its exact source authority")
        object.__setattr__(
            self, "detached_dead_handler_component_source_results", source_results,
        )
        object.__setattr__(
            self, "detached_dead_handler_component_phase_results", phase_results,
        )
        if self.retirement_phase_result is not None:
            result = self.retirement_phase_result
            if type(result) is not RetirementPhaseResult:
                raise TypeError("retirement_phase_result must be RetirementPhaseResult or None")
            result.__post_init__()
            catalog = self.retirement_candidate_catalog
            receipt_catalog = self.preparation_receipt.retirement_candidate_catalog
            if catalog is None or receipt_catalog != catalog or result.catalog_id != catalog.catalog_id:
                raise ValueError("retirement phase result requires the case candidate catalog")
            if (
                result.phase is not self.phase
                or result.claim_id not in {claim.claim_id for claim in self.claims}
                or result.source_fingerprint != self.source_fingerprint
                or result.candidate_fingerprint != self.candidate_fingerprint
                or result.source_generation != self.preparation_receipt.source_generation
                or result.candidate_generation != self.candidate_generation
            ):
                raise ValueError("retirement phase result coordinates are not sealed")
            candidate_ids = {item.block_ref: item.candidate_id for item in catalog.candidates}
            if set(item.block_ref for item in result.members) != set(catalog.member_refs):
                raise ValueError("retirement phase result is not exact case plan coverage")
            if any(item.candidate_id != candidate_ids.get(item.block_ref) for item in result.members):
                raise ValueError("retirement phase result candidate evidence drifted")
            _validate_retirement_phase_result_inventory_bindings(
                result, self.source_inventory, self.candidate_inventory,
            )
            from .bind import validate_retirement_phase_result
            validate_retirement_phase_result(result)
        elif self.retirement_candidate_catalog is not None:
            raise ValueError("retirement candidate catalog requires a bound phase result")
        terminal_results = _validate_terminal_cycle_phase_results(
            self.terminal_cycle_phase_results,
            self.claims,
            phase=self.phase,
            source_fingerprint=self.source_fingerprint,
            candidate_fingerprint=self.candidate_fingerprint,
            source_generation=self.preparation_receipt.source_generation,
            candidate_generation=self.candidate_generation,
            expected_source_bindings=self.source_inventory.bindings,
            expected_candidate_bindings=self.candidate_inventory.bindings,
            source_inventory=self.source_inventory,
            candidate_inventory=self.candidate_inventory,
        )
        object.__setattr__(self, "terminal_cycle_phase_results", terminal_results)
        has_retirement = any(
            type(claim) is RetiredDispatcherInfrastructureClaim for claim in self.claims
        )
        if has_retirement:
            if self.retirement_candidate_catalog is None or self.preparation_receipt.retirement_candidate_catalog != self.retirement_candidate_catalog:
                raise ValueError("retirement case candidate records must share the exact catalog")
        elif (
            self.retirement_candidate_catalog is not None
            or self.preparation_receipt.retirement_candidate_catalog is not None
        ):
            raise ValueError("retirement catalog is present without a retirement claim")
        if self.preparation_receipt_id != self.preparation_receipt.receipt_id:
            raise ValueError("preparation_receipt_id does not match preparation_receipt")
        if self.preparation_receipt.source_fingerprint != self.source_fingerprint:
            raise ValueError("preparation_receipt source_fingerprint does not match case")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _generation(self.candidate_generation, "candidate_generation")
        for name in ("claims", "subjects", "bindings", "conditional_relations", "required_obligations", "evidence", "justifications"):
            object.__setattr__(self, name, _tuple(getattr(self, name), name))
        if any(type(claim) not in (RetiredDispatcherInfrastructureClaim, DetachedDeadHandlerComponentClaim, EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim, LocalAliasEffectScalarizationClaim, TerminalCycleBreakClaim) for claim in self.claims):
            raise TypeError("claims must contain closed UnflattenClaim values")
        if any(type(subject) is not SemanticSubjectRef for subject in self.subjects):
            raise TypeError("subjects must contain SemanticSubjectRef values")
        if any(type(binding) is not PhaseSubjectBinding for binding in self.bindings):
            raise TypeError("bindings must contain PhaseSubjectBinding values")
        if any(type(relation) is not ConditionalSubjectRelation for relation in self.conditional_relations):
            raise TypeError("conditional_relations must contain ConditionalSubjectRelation values")
        if any(type(key) is not ObligationKey for key in self.required_obligations):
            raise TypeError("required_obligations must contain ObligationKey values")
        if not self.required_obligations:
            raise ValueError("a semantic safety case must contain obligations")
        if len(set(self.required_obligations)) != len(self.required_obligations):
            raise ValueError("required_obligations must be unique")
        if any(type(item) is not AuthorityEvidence for item in self.evidence):
            raise TypeError("evidence must contain AuthorityEvidence values")
        if any(type(item) is not AuthorityJustification for item in self.justifications):
            raise TypeError("justifications must contain AuthorityJustification values")
        # Compact case IDs compose independently sealed child IDs.  Revalidate
        # every model-owned occurrence behind those IDs exactly once at this
        # boundary so a stale or validly reminted parent ID cannot conceal a
        # mutated claim, subject, evidence payload, binding, or justification.
        # The visited set is construction-local; authority never depends on a
        # process-global cache or on a digest without its validated object.
        validated_occurrences: set[int] = set()

        def validate_occurrence(value: object) -> None:
            if type(value) is tuple:
                for nested in value:
                    validate_occurrence(nested)
                return
            if (
                not is_dataclass(value)
                or type(value).__module__ != __name__
                or type(value) is SemanticSafetyCase
            ):
                return
            identity = id(value)
            if identity in validated_occurrences:
                return
            validated_occurrences.add(identity)
            for record_field in fields(value):
                validate_occurrence(getattr(value, record_field.name))
            post_init = getattr(type(value), "__post_init__", None)
            if post_init is not None:
                post_init(value)

        validate_occurrence(self.claims)
        validate_occurrence(self.subjects)
        validate_occurrence(self.bindings)
        validate_occurrence(self.conditional_relations)
        validate_occurrence(self.required_obligations)
        validate_occurrence(self.evidence)
        validate_occurrence(self.justifications)
        validate_occurrence(self.obligation_index)
        if tuple(sorted(self.subjects, key=lambda item: item.subject_id)) != self.subjects:
            raise ValueError("subjects must be in canonical subject-id order")
        if tuple(sorted(self.claims, key=lambda item: item.claim_id)) != self.claims:
            raise ValueError("claims must be in canonical claim-id order")
        if tuple(sorted(self.conditional_relations, key=lambda item: (item.source_subject_id, item.target_subject_id, item.dimension.value, item.provenance_id))) != self.conditional_relations:
            raise ValueError("conditional relations must be in canonical order")
        if tuple(sorted(self.bindings, key=lambda item: item.subject.subject_id)) != self.bindings:
            raise ValueError("bindings must be in canonical subject-id order")
        if tuple(sorted(self.required_obligations, key=lambda item: (item.subject.subject_id, item.dimension.value))) != self.required_obligations:
            raise ValueError("required obligations must be in canonical order")
        if tuple(sorted(self.evidence, key=lambda item: item.evidence_id)) != self.evidence:
            raise ValueError("evidence must be in canonical evidence-id order")
        if tuple(sorted(self.justifications, key=lambda item: item.justification_id)) != self.justifications:
            raise ValueError("justifications must be in canonical justification-id order")
        _validate_terminal_cycle_evidence(
            self.terminal_cycle_phase_results,
            self.evidence,
            self.claims,
            self.phase,
        )
        if type(self.obligation_index) is not ObligationEvidenceIndex:
            raise TypeError("obligation_index must be an ObligationEvidenceIndex")
        if type(self.phase_metrics) is not SemanticPhaseMetrics:
            raise TypeError("phase_metrics must be SemanticPhaseMetrics")
        if type(self.source_inventory) is not SemanticGraphInventory:
            raise TypeError("source_inventory must be SemanticGraphInventory")
        validate_semantic_graph_inventory(self.source_inventory)
        if self.source_inventory.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("source_inventory must be a producer forecast inventory")
        if self.source_inventory.graph_fingerprint != self.source_fingerprint:
            raise ValueError("source_inventory fingerprint does not match source_fingerprint")
        if self.source_inventory.generation != self.preparation_receipt.source_generation:
            raise ValueError("source_inventory generation does not match preparation_receipt")
        if self.source_inventory.inventory_digest != self.preparation_receipt.source_inventory_digest:
            raise ValueError("source_inventory digest does not match preparation_receipt")
        if type(self.candidate_inventory) is not SemanticGraphInventory:
            raise TypeError("candidate_inventory must be SemanticGraphInventory")
        validate_semantic_graph_inventory(self.candidate_inventory)
        if (
            self.candidate_inventory.graph_fingerprint
            != self.preparation_receipt.candidate_fingerprint
            or self.candidate_inventory.generation
            != self.preparation_receipt.candidate_generation
            or self.candidate_inventory.inventory_digest
            != self.preparation_receipt.candidate_inventory_digest
        ):
            raise ValueError(
                "candidate_inventory does not match preparation receipt"
            )
        if any(
            claim.source_generation != self.source_inventory.generation
            for claim in self.claims
        ):
            raise ValueError("claims must use the exact source generation")
        source_subject_ids = _tuple(self.source_subject_ids, "source_subject_ids", sort=True)
        if any(type(value) is not str for value in source_subject_ids):
            raise TypeError("source_subject_ids must contain strings")
        if len(set(source_subject_ids)) != len(source_subject_ids):
            raise ValueError("source_subject_ids must be unique")
        if not set(source_subject_ids) <= {subject.subject_id for subject in self.subjects}:
            raise ValueError("source subject partition contains a foreign subject")
        if source_subject_ids != self.source_inventory.source_subject_ids:
            raise ValueError("source subject partition does not match source_inventory")
        case_source_subjects = tuple(
            subject for subject in self.subjects if subject.subject_id in set(source_subject_ids)
        )
        if case_source_subjects != self.source_inventory.subjects:
            raise ValueError("source subjects do not match source_inventory")
        object.__setattr__(self, "source_subject_ids", source_subject_ids)
        if type(self.source_bindings) is not tuple:
            raise TypeError("source_bindings must be an exact tuple")
        source_bindings = self.source_bindings
        if any(type(binding) is not PhaseSubjectBinding for binding in source_bindings):
            raise TypeError("source_bindings must contain PhaseSubjectBinding values")
        if source_bindings != tuple(sorted(source_bindings, key=lambda item: item.subject.subject_id)):
            raise ValueError("source_bindings must be in canonical subject-id order")
        if tuple(binding.subject.subject_id for binding in source_bindings) != source_subject_ids:
            raise ValueError("source_bindings must exactly cover source_subject_ids")
        if source_bindings != self.source_inventory.bindings:
            raise ValueError("source_bindings must exactly match source_inventory")
        if authority_id(tuple(sorted(source_bindings, key=lambda item: item.subject.subject_id))) != self.preparation_receipt.source_binding_digest:
            raise ValueError("source_bindings digest does not match preparation_receipt")
        if any(
            binding.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST
            or binding.graph_fingerprint != self.source_fingerprint
            for binding in source_bindings
        ):
            raise ValueError("source_bindings must be exact source-phase bindings with the source fingerprint")
        if source_bindings and len({binding.generation for binding in source_bindings}) != 1:
            raise ValueError("source_bindings must share one source generation")
        subjects_by_id = {subject.subject_id: subject for subject in self.subjects}
        if any(subjects_by_id.get(binding.subject.subject_id) != binding.subject for binding in source_bindings):
            raise ValueError("source_binding subject is not the exact case subject")
        if self.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST and source_bindings != self.bindings:
            raise ValueError("producer case bindings must equal source_bindings")
        object.__setattr__(self, "source_bindings", source_bindings)
        if tuple(cell.key for cell in self.obligation_index.cells) != self.required_obligations:
            raise ValueError("obligation index must exactly cover required obligations")
        if self.case_id != case_id(self):
            raise ValueError("case_id does not match canonical case content")
        # Reuse the evaluator's contextual rule validator at the canonical
        # decode/model boundary so forged IDs cannot bypass premise semantics.
        from .evaluate import _validate_justification_graph
        _validate_justification_graph(
            self.justifications, self.required_obligations, self.evidence,
            self.phase, self.claims, self.conditional_relations,
            candidate_fingerprint=self.candidate_fingerprint,
            candidate_generation=self.candidate_generation,
            bindings=self.bindings, subjects=self.subjects,
            source_subject_ids=self.source_subject_ids,
        )


@dataclass(frozen=True, slots=True)
class UnflattenAuthorityVerdict:
    accepted: bool
    phase: UnflattenAuthorityPhase
    reason: UnflattenAuthorityReason
    authority_id: str | None
    binding_id: str | None
    case_id: str | None
    candidate_fingerprint: str
    safety_case: SemanticSafetyCase | None
    failed_obligations: tuple[FailedObligation, ...]
    observed_acceptance: "ObservedUnflattenAuthorityAccepted | None" = None
    loss_ledger: SemanticLossLedger | None = None
    rejection_detail: str | None = None

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be bool")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _enum(self.reason, UnflattenAuthorityReason, "reason")
        for name in ("authority_id", "binding_id", "case_id"):
            value = getattr(self, name)
            if value is not None:
                _id(value, name)
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        if self.safety_case is not None and type(self.safety_case) is not SemanticSafetyCase:
            raise TypeError("safety_case must be SemanticSafetyCase or None")
        if self.safety_case is not None:
            if self.case_id != self.safety_case.case_id or self.authority_id != self.safety_case.authority_id:
                raise ValueError("verdict IDs must match its safety case")
            if self.phase is not self.safety_case.phase:
                raise ValueError("verdict phase does not match its safety case")
            if self.candidate_fingerprint != self.safety_case.candidate_fingerprint:
                raise ValueError("verdict fingerprint does not match its safety case")
        elif self.case_id is not None:
            raise ValueError("a verdict without a safety case cannot carry a case ID")
        failed = _tuple(self.failed_obligations, "failed_obligations")
        if any(type(item) is not FailedObligation for item in failed):
            raise TypeError("failed_obligations must contain FailedObligation values")
        object.__setattr__(self, "failed_obligations", failed)
        if self.safety_case is not None:
            expected_failed = tuple(
                FailedObligation(cell.key, cell.state)
                for cell in self.safety_case.obligation_index.cells
                if cell.state is not ObligationState.SATISFIED
            )
            if failed != expected_failed:
                raise ValueError("verdict failed obligations must match its safety case")
            graph_mismatch = any(
                binding.graph_fingerprint != self.safety_case.candidate_fingerprint
                or binding.generation != self.safety_case.candidate_generation
                for binding in self.safety_case.bindings
                if binding.subject.kind is SemanticSubjectKind.BLOCK
            )
            binding_failed = any(
                item.state is ObligationState.VIOLATED
                and item.key.dimension is SafetyDimension.IDENTITY_BINDING
                for item in expected_failed
            )
            expected_reason = (
                UnflattenAuthorityReason.GRAPH_GENERATION_MISMATCH
                if graph_mismatch else
                {
                    UnflattenAuthorityPhase.PRODUCER_FORECAST: UnflattenAuthorityReason.SOURCE_BINDING_FAILED,
                    UnflattenAuthorityPhase.PROJECTED_PREFLIGHT: UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
                    UnflattenAuthorityPhase.OBSERVED_POST_APPLY: UnflattenAuthorityReason.LIVE_BINDING_FAILED,
                }[self.phase]
                if binding_failed else
                UnflattenAuthorityReason.OBLIGATION_INCONSISTENT
                if any(item.state is ObligationState.INCONSISTENT for item in expected_failed) else
                UnflattenAuthorityReason.OBLIGATION_VIOLATED
                if any(item.state is ObligationState.VIOLATED for item in expected_failed) else
                UnflattenAuthorityReason.OBLIGATION_UNPROVEN
                if expected_failed else UnflattenAuthorityReason.ACCEPTED
            )
            if self.reason is not expected_reason:
                raise ValueError("verdict reason does not match deterministic case priority")
        if self.accepted and (self.reason is not UnflattenAuthorityReason.ACCEPTED or self.safety_case is None or failed):
            raise ValueError("accepted verdict requires an accepted nonempty case")
        if not self.accepted and self.reason is UnflattenAuthorityReason.ACCEPTED:
            raise ValueError("rejected verdict cannot use accepted reason")
        if not self.accepted and self.safety_case is None and failed:
            raise ValueError("a pre-case rejection cannot carry failed obligations")
        if self.observed_acceptance is not None:
            if type(self.observed_acceptance) is not ObservedUnflattenAuthorityAccepted:
                raise TypeError("observed_acceptance must be ObservedUnflattenAuthorityAccepted or None")
            if (
                not self.accepted
                or self.phase is not UnflattenAuthorityPhase.OBSERVED_POST_APPLY
                or self.safety_case is not self.observed_acceptance.observed_case
                or self.binding_id != self.observed_acceptance.bound_authority.binding_id
            ):
                raise ValueError("observed acceptance does not match exact observed verdict")
        if self.loss_ledger is not None:
            if type(self.loss_ledger) is not SemanticLossLedger:
                raise TypeError("loss_ledger must be SemanticLossLedger or None")
            if (
                self.safety_case is None
                or self.loss_ledger.case is not self.safety_case
                or self.loss_ledger.phase is not self.phase
                or self.loss_ledger.authority_id != self.authority_id
                or self.loss_ledger.case_id != self.case_id
            ):
                raise ValueError("loss ledger does not match exact verdict occurrence")
        if (
            self.observed_acceptance is not None
            and self.loss_ledger is not self.observed_acceptance.observed_ledger
        ):
            raise ValueError("observed verdict must retain its exact observed ledger")
        if self.rejection_detail is not None:
            # A rejection that carries no subject-keyed obligation must still
            # name what it rejected; an unexplained ``failed=()`` is not a
            # readable verdict.
            if type(self.rejection_detail) is not str or not self.rejection_detail:
                raise TypeError("rejection_detail must be a nonempty string or None")
            if self.accepted:
                raise ValueError("an accepted verdict cannot carry a rejection detail")
            if len(self.rejection_detail) > 640:
                raise ValueError("rejection_detail must stay bounded")


@dataclass(frozen=True, slots=True)
class UnflattenAuthorityNotApplicable:
    route: Literal[UnflattenPlanRoute.ORDINARY]

    def __post_init__(self) -> None:
        if self.route is not UnflattenPlanRoute.ORDINARY:
            raise ValueError("not-applicable route must be ordinary")


@runtime_checkable
class PatchPlanAuthority(Protocol):
    plan_id: str
    snapshot_id: str
    source_generation: int | None
    source_maturity: MaturityEnvelope | None
    source_coordinates: tuple[tuple[NativeBlockRef | LogicalBlockRef, int], ...]


@dataclass(frozen=True, slots=True)
class PreparedUnflattenAuthority:
    authority_id: str
    route: UnflattenPlanRoute
    owning_plan: PatchPlanAuthority
    proposal: ProposedUnflattenContract
    claims: tuple[UnflattenClaim, ...]
    source_route_authority: SourceBoundRouteAuthority
    projected_route_realization: ProjectedRouteRealization
    snapshot_id: str
    source_maturity: MaturityEnvelope | None
    source_coordinate_digest: str
    source_fingerprint: str
    projected_fingerprint: str
    source_generation: int
    projected_generation: int
    source_bindings: tuple[PhaseSubjectBinding, ...]
    projected_bindings: tuple[PhaseSubjectBinding, ...]
    projected_case: SemanticSafetyCase
    source_inventory: SemanticGraphInventory
    # This is the transaction-owned projected semantic-loss authority.  It is
    # deliberately an occurrence, not a serial-set projection: every
    # projected gate consumes this exact ledger with ``projected_case``.
    projected_loss_ledger: SemanticLossLedger
    source_inputs: DerivedUnflattenPreparationInputs | None = None
    preparation_attempt_id: TransactionAttemptId | None = None
    entry_endpoint_liveness_receipts: tuple[BoundEntryEndpointLivenessAllowance, ...] = ()

    @property
    def attempt_id(self) -> TransactionAttemptId | None:
        """Exact attempt that produced this preparation, if supplied."""

        return self.preparation_attempt_id

    def __post_init__(self) -> None:
        _id(self.authority_id, "authority_id")
        _enum(self.route, UnflattenPlanRoute, "route")
        if not isinstance(self.owning_plan, PatchPlanAuthority):
            raise TypeError("owning_plan must satisfy PatchPlanAuthority")
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("proposal must be ProposedUnflattenContract")
        if type(self.source_route_authority) is not SourceBoundRouteAuthority:
            raise TypeError("source_route_authority must be SourceBoundRouteAuthority")
        if type(self.projected_route_realization) is not ProjectedRouteRealization:
            raise TypeError("projected_route_realization must be ProjectedRouteRealization")
        if self.projected_route_realization.source_authority is not self.source_route_authority:
            raise ValueError("prepared realization must retain exact source authority")
        # A snapshot ID is an external transaction coordinate (for example,
        # ``<mba-session>:m<maturity>:g<generation>``), not a content-addressed
        # semantic authority ID.  Preserve it exactly and validate only the
        # non-empty string contract shared by PatchPlan/CfgProjection.
        _text(self.snapshot_id, "snapshot_id")
        if self.source_maturity is not None and type(self.source_maturity) is not MaturityEnvelope:
            raise TypeError("source_maturity must be MaturityEnvelope or None")
        _id(self.source_coordinate_digest, "source_coordinate_digest")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.projected_fingerprint, "projected_fingerprint")
        _generation(self.source_generation, "source_generation")
        _generation(self.projected_generation, "projected_generation")
        for name in ("claims", "source_bindings", "projected_bindings"):
            values = _tuple(getattr(self, name), name)
            object.__setattr__(self, name, values)
        if type(self.projected_case) is not SemanticSafetyCase:
            raise TypeError("projected_case must be SemanticSafetyCase")
        if type(self.projected_loss_ledger) is not SemanticLossLedger:
            raise TypeError("projected_loss_ledger must be SemanticLossLedger")
        if self.projected_loss_ledger.case is not self.projected_case:
            raise ValueError("prepared projected loss ledger must own the exact projected case")
        if type(self.source_inventory) is not SemanticGraphInventory:
            raise TypeError("source_inventory must be SemanticGraphInventory")
        validate_semantic_graph_inventory(self.source_inventory)
        if self.source_inventory.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("prepared source inventory must be producer forecast")
        if self.source_inputs is not None and type(self.source_inputs) is not DerivedUnflattenPreparationInputs:
            raise TypeError("source_inputs must be DerivedUnflattenPreparationInputs or None")
        receipts = _tuple(self.entry_endpoint_liveness_receipts, "entry_endpoint_liveness_receipts")
        if any(type(item) is not BoundEntryEndpointLivenessAllowance for item in receipts):
            raise TypeError("entry endpoint liveness receipts must be bound allowances")
        if {item.allowance for item in receipts} != set(self.proposal.entry_endpoint_liveness_allowances):
            raise ValueError("prepared entry liveness receipts do not exactly cover proposal allowances")
        if len({item.binding_id for item in receipts}) != len(receipts):
            raise ValueError("prepared entry liveness receipt IDs must be unique")
        if tuple(item.binding_id for item in receipts) != tuple(
            sorted(item.binding_id for item in receipts)
        ):
            raise ValueError("prepared entry liveness receipts must be canonical")
        route_proof_ids = {
            proof.proof_id for proof in self.proposal.route_evidence.route_proofs
        }
        for receipt in receipts:
            if receipt.route_proof_id not in route_proof_ids:
                raise ValueError("prepared entry liveness receipt names a foreign route proof")
            if (
                receipt.source_fingerprint != self.source_fingerprint
                or receipt.projected_fingerprint != self.projected_fingerprint
                or receipt.source_generation != self.source_generation
                or receipt.projected_generation != self.projected_generation
                or receipt.source_inventory_digest != self.source_inventory.inventory_digest
            ):
                raise ValueError("prepared entry liveness receipt coordinates drifted")
            if self.source_inputs is not None and (
                receipt.projected_inventory_digest
                != self.source_inputs.candidate_inventory.inventory_digest
            ):
                raise ValueError("prepared entry liveness receipt projected inventory drifted")
        object.__setattr__(self, "entry_endpoint_liveness_receipts", receipts)
        if self.source_inputs is not None:
            if self.source_route_authority is not self.source_inputs.source_route_authority:
                raise ValueError("prepared source route authority must be the exact input object")
            if self.projected_route_realization is not self.source_inputs.projected_route_realization:
                raise ValueError("prepared projected realization must be the exact input object")
        if self.source_inputs is not None and self.source_inventory is not self.source_inputs.source_inventory:
            raise ValueError("prepared source inventory must be the exact source input object")
        if self.source_inputs is not None:
            if (
                self.source_fingerprint != self.source_inputs.source_inventory.graph_fingerprint
                or self.projected_fingerprint != self.source_inputs.candidate_inventory.graph_fingerprint
                or self.source_generation != self.source_inputs.source_inventory.generation
                or self.projected_generation != self.source_inputs.candidate_inventory.generation
                or self.source_bindings != self.source_inputs.source_inventory.bindings
                or self.projected_bindings != self.source_inputs.candidate_inventory.bindings
            ):
                raise ValueError("prepared source bindings/fingerprints do not match source inputs")
        if (
            self.source_route_authority.proposal is not self.proposal
            or self.source_route_authority.source_fingerprint != self.source_fingerprint
            or self.source_route_authority.source_generation != self.source_generation
            or self.projected_route_realization.projected_fingerprint != self.projected_fingerprint
            or self.projected_route_realization.projected_generation != self.projected_generation
        ):
            raise ValueError("prepared route authority does not match coordinates")
        if self.preparation_attempt_id is not None and type(self.preparation_attempt_id) is not TransactionAttemptId:
            raise TypeError("preparation_attempt_id must be TransactionAttemptId or None")
        if self.owning_plan.plan_id != self.proposal.plan_id:
            raise ValueError("owning plan does not match proposal")
        if self.preparation_attempt_id is not None:
            if self.preparation_attempt_id.plan_id != self.proposal.plan_id:
                raise ValueError("preparation attempt does not match proposal")
            if self.preparation_attempt_id.session_id == "":
                raise ValueError("preparation attempt session must not be blank")
        if self.owning_plan.snapshot_id != self.snapshot_id:
            raise ValueError("snapshot does not match owning plan")
        if self.projected_case.authority_id != self.authority_id:
            raise ValueError("projected case does not match authority")
        if self.projected_case.phase is not UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("prepared authority requires a projected case")
        if self.projected_case.candidate_fingerprint != self.projected_fingerprint:
            raise ValueError("projected fingerprint does not match case")
        if self.projected_case.candidate_generation != self.projected_generation:
            raise ValueError("projected generation does not match case")
        if tuple(self.projected_case.bindings) != tuple(sorted(self.projected_bindings, key=lambda item: item.subject.subject_id)):
            raise ValueError("projected bindings do not match case")
        if self.owning_plan.source_generation is not None and self.owning_plan.source_generation != self.source_generation:
            raise ValueError("source generation does not match owning plan")
        if self.source_maturity != self.owning_plan.source_maturity:
            raise ValueError("source maturity does not match owning plan")
        # PatchPlan.source_coordinates cover the complete source graph, while
        # the semantic catalog intentionally omits the instructionless
        # synthetic STOP used only for structural bookkeeping.  Seal the full
        # coordinate map, require exact catalog coverage, and admit only those
        # extra rows that the source inventory itself classifies as that
        # unowned STOP.
        plan_coordinate_rows = _canonical_source_coordinates(
            self.owning_plan.source_coordinates
        )
        plan_coordinates = dict(plan_coordinate_rows)
        if len(plan_coordinates) != len(plan_coordinate_rows):
            raise ValueError("owning plan contains duplicate source coordinate references")
        catalog_refs = {
            block.block_ref for block in self.proposal.source_identity_catalog.blocks
        }
        if not catalog_refs <= set(plan_coordinates):
            raise ValueError("owning plan source coordinates omit proposal catalog rows")
        expected_coordinates = _canonical_source_coordinates(
            (block.block_ref, plan_coordinates[block.block_ref])
            for block in self.proposal.source_identity_catalog.blocks
        )
        inventory_blocks = {row.serial: row for row in self.source_inventory.blocks}
        plan_serials = tuple(serial for _ref, serial in plan_coordinate_rows)
        if (
            len(set(plan_serials)) != len(plan_serials)
            or set(plan_serials) != set(inventory_blocks)
        ):
            raise ValueError("owning plan source coordinates do not cover the source inventory")
        extra_coordinates = tuple(
            (ref, serial)
            for ref, serial in plan_coordinate_rows
            if ref not in catalog_refs
        )
        dag_endpoint_subjects = tuple({
            subject.subject_id: subject
            for claim in self.proposal.claims
            if type(claim) is EquivalentSemanticRouteClaim
            for subject in claim.dag_endpoint_subjects
        }.values())
        logical_exit_coordinates = _claimed_logical_function_exit_coordinates(
            self.proposal
        )
        dag_endpoint_coordinates = {
            (subject.locator.block_ref, subject.locator.serial)
            for subject in dag_endpoint_subjects
        }
        if not logical_exit_coordinates <= set(extra_coordinates):
            raise ValueError(
                "owning plan source coordinates omit a selected logical function exit"
            )
        if any(
            type(ref) is not LogicalBlockRef
            or (
                (ref, serial) not in logical_exit_coordinates
                and not _is_unowned_structural_stop_row(inventory_blocks[serial])
                and not (
                    _is_exact_logical_function_exit_row(inventory_blocks[serial])
                    and inventory_blocks[serial].predecessor_serials
                    and all(
                        predecessor in inventory_blocks
                        and serial
                        in inventory_blocks[predecessor].successor_serials
                        for predecessor
                        in inventory_blocks[serial].predecessor_serials
                    )
                )
            )
            or (
                (ref, serial) in logical_exit_coordinates
                and not _is_exact_logical_function_exit_row(inventory_blocks[serial])
            )
            for ref, serial in extra_coordinates
        ):
            raise ValueError(
                "owning plan contains a non-catalog semantic source coordinate"
            )
        if self.source_coordinate_digest != authority_id(plan_coordinate_rows):
            raise ValueError("source coordinate digest does not match the owning plan")
        source_binding_coordinates = _canonical_source_coordinates(
            (binding.block_ref, binding.serial)
            for binding in self.source_bindings
            if binding.status is SubjectBindingStatus.UNIQUE
            and binding.block_ref in catalog_refs and binding.serial is not None
        )
        if frozenset(source_binding_coordinates) != frozenset(expected_coordinates):
            raise ValueError("source bindings do not cover the proposal catalog")
        endpoint_bindings = {
            binding.subject.subject_id: binding
            for binding in self.source_bindings
            if binding.subject.role is SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT
        }
        if set(endpoint_bindings) != {
            subject.subject_id for subject in dag_endpoint_subjects
        } or any(
            binding.status is not SubjectBindingStatus.UNIQUE
            or binding.block_ref != subject.locator.block_ref
            or binding.serial != subject.locator.serial
            or binding.anchor_ea is not None
            or binding.native_instruction_eas
            for subject in dag_endpoint_subjects
            for binding in (endpoint_bindings[subject.subject_id],)
        ):
            raise ValueError(
                "source bindings do not exactly cover selected logical DAG endpoints"
            )
        source_subject_ids = self.projected_case.source_subject_ids
        if source_subject_ids != self.source_inventory.source_subject_ids:
            raise ValueError("prepared case/source inventory partition differs")
        if tuple(binding.subject.subject_id for binding in self.source_bindings) != source_subject_ids:
            raise ValueError("source bindings must cover every case source subject exactly")
        source_subjects = tuple(
            subject for subject in self.projected_case.subjects
            if subject.subject_id in set(source_subject_ids)
        )
        if source_subjects != self.source_inventory.subjects:
            raise ValueError("prepared case source subjects differ from source inventory")
        if any(
            binding.subject != subject
            for subject in source_subjects
            for binding in self.source_bindings
            if binding.subject.subject_id == subject.subject_id
        ):
            raise ValueError("source binding subject identity does not match the projected source subject")
        if self.source_inputs is not None:
            candidate_bindings = self.source_inputs.candidate_inventory.bindings
            if self.projected_bindings != candidate_bindings:
                raise ValueError("projected bindings must exactly match candidate inventory")
            if self.projected_bindings != self.projected_case.bindings:
                raise ValueError("projected bindings must exactly match projected case")
        if any(
            binding.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST
            or binding.graph_fingerprint != self.source_fingerprint
            or binding.generation != self.source_generation
            for binding in self.source_bindings
        ):
            raise ValueError("source bindings do not match the prepared source snapshot")
        if any(
            binding.phase is not UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
            or binding.graph_fingerprint != self.projected_fingerprint
            or binding.generation != self.projected_generation
            for binding in self.projected_bindings
        ):
            raise ValueError("projected bindings do not match the prepared projected snapshot")
        if tuple(self.claims) != tuple(self.projected_case.claims):
            raise ValueError("prepared claims must exactly match projected case claims")


@dataclass(frozen=True, slots=True)
class BoundUnflattenAuthority:
    binding_id: str
    prepared: PreparedUnflattenAuthority
    attempt_id: TransactionAttemptId
    session_id: str
    generation: int
    live_maturity: MaturityEnvelope
    live_bindings: tuple[tuple[CfgBlockRef, int], ...]
    patch_binding: BoundPatchPlan
    entry_endpoint_liveness_receipts: tuple[BoundEntryEndpointLivenessAllowance, ...] = ()

    def __post_init__(self) -> None:
        _id(self.binding_id, "binding_id")
        if type(self.prepared) is not PreparedUnflattenAuthority:
            raise TypeError("prepared must be PreparedUnflattenAuthority")
        # The binder consumes the exact prepared occurrence.  Its public
        # boundary validates the patch binding and identity relations; nested
        # semantic content was sealed during preparation and must not be
        # recursively replayed by each carrier construction.
        if type(self.attempt_id) is not TransactionAttemptId:
            raise TypeError("attempt_id must be TransactionAttemptId")
        _text(self.session_id, "session_id")
        _generation(self.generation)
        if self.attempt_id.session_id != self.session_id:
            raise ValueError("attempt session does not match binding session")
        if self.attempt_id.generation != self.generation:
            raise ValueError("attempt generation does not match binding generation")
        if self.attempt_id.plan_id != self.prepared.proposal.plan_id:
            raise ValueError("attempt plan does not match prepared proposal")
        if type(self.live_maturity) is not MaturityEnvelope:
            raise TypeError("live_maturity must be MaturityEnvelope")
        if type(self.patch_binding) is not BoundPatchPlan:
            raise TypeError("patch_binding must be BoundPatchPlan")
        validate_bound_patch_plan(self.patch_binding)
        if self.patch_binding.plan is not self.prepared.owning_plan:
            raise ValueError("patch binding plan does not match prepared authority")
        if self.patch_binding.plan.unflatten_proposal is not self.prepared.proposal:
            raise ValueError("patch binding proposal does not match prepared authority")
        if self.patch_binding.attempt_id is not self.attempt_id:
            raise ValueError("patch binding attempt does not match authority")
        if (
            self.patch_binding.session_id != self.session_id
            or self.patch_binding.generation != self.generation
        ):
            raise ValueError("patch binding session/generation does not match authority")
        if self.patch_binding.maturity is not self.live_maturity:
            raise ValueError("patch binding maturity does not match authority")
        if self.entry_endpoint_liveness_receipts != self.prepared.entry_endpoint_liveness_receipts:
            raise ValueError("bound entry liveness receipts differ from prepared authority")
        if self.binding_id != bound_unflatten_binding_id(
            self.prepared, self.patch_binding
        ):
            raise ValueError("binding_id does not match exact bound authority")
        values = _tuple(self.live_bindings, "live_bindings")
        if self.patch_binding.bindings != values:
            raise ValueError("patch binding rows do not match authority rows")
        for ref, serial in values:
            _cfg_ref(ref)
            _nonnegative(serial, "live binding serial")
        object.__setattr__(self, "live_bindings", values)


@dataclass(frozen=True, slots=True)
class ObservedUnflattenAuthorityAccepted:
    """One accepted observed realization closed over its bound authority."""

    bound_authority: BoundUnflattenAuthority
    observed_patch_binding: ObservedPatchBinding
    projected_ledger: SemanticLossLedger
    observed_case: SemanticSafetyCase
    observed_ledger: SemanticLossLedger
    delta: ObservedSemanticLossDelta

    def __post_init__(self) -> None:
        if type(self.bound_authority) is not BoundUnflattenAuthority:
            raise TypeError("bound_authority must be BoundUnflattenAuthority")
        if type(self.observed_patch_binding) is not ObservedPatchBinding:
            raise TypeError("observed_patch_binding must be ObservedPatchBinding")
        validate_observed_patch_binding(self.observed_patch_binding)
        if self.observed_patch_binding.bound_plan is not self.bound_authority.patch_binding:
            raise ValueError(
                "observed patch binding must retain exact bound patch authority"
            )
        prepared = self.bound_authority.prepared
        if self.projected_ledger is not prepared.projected_loss_ledger:
            raise ValueError("observed acceptance must retain exact projected ledger")
        if type(self.observed_case) is not SemanticSafetyCase:
            raise TypeError("observed_case must be SemanticSafetyCase")
        if type(self.observed_ledger) is not SemanticLossLedger:
            raise TypeError("observed_ledger must be SemanticLossLedger")
        if self.observed_ledger.case is not self.observed_case:
            raise ValueError("observed ledger must retain exact observed case")
        if type(self.delta) is not ObservedSemanticLossDelta:
            raise TypeError("delta must be ObservedSemanticLossDelta")
        if (
            self.observed_case.authority_id != prepared.authority_id
            or self.observed_case.source_fingerprint != prepared.source_fingerprint
            or self.observed_case.phase is not UnflattenAuthorityPhase.OBSERVED_POST_APPLY
            or self.delta.projected_case_id != prepared.projected_case.case_id
            or self.delta.observed_case_id != self.observed_case.case_id
            or self.delta.projected_ledger_id != self.projected_ledger.ledger_id
            or self.delta.observed_ledger_id != self.observed_ledger.ledger_id
        ):
            raise ValueError("observed acceptance authority coordinates drifted")
        projected_subject_ids = {
            row.source_subject.subject_id for row in self.projected_ledger.rows
        }
        expected_delta_rows = tuple(
            row for row in self.observed_ledger.rows
            if row.source_subject.subject_id not in projected_subject_ids
        )
        if (
            len(self.delta.rows) != len(expected_delta_rows)
            or any(actual is not expected for actual, expected in zip(
                self.delta.rows, expected_delta_rows,
            ))
            or any(row.case is not self.observed_case for row in self.delta.rows)
        ):
            raise ValueError(
                "observed delta must be the exact observed-only ledger rows"
            )


@dataclass(frozen=True, slots=True)
class UnflattenAuthorityPreparationAccepted:
    prepared: PreparedUnflattenAuthority
    verdict: UnflattenAuthorityVerdict

    def __post_init__(self) -> None:
        if type(self.prepared) is not PreparedUnflattenAuthority:
            raise TypeError("prepared must be PreparedUnflattenAuthority")
        if type(self.verdict) is not UnflattenAuthorityVerdict or not self.verdict.accepted:
            raise ValueError("preparation accepted requires an accepted verdict")
        if (
            self.verdict.authority_id != self.prepared.authority_id
            or self.verdict.case_id != self.prepared.projected_case.case_id
            or self.verdict.loss_ledger is not self.prepared.projected_loss_ledger
        ):
            raise ValueError("preparation verdict does not match prepared authority")


@dataclass(frozen=True, slots=True)
class ProposalValidationFailure:
    """Typed proposal boundary failure carried into preparation diagnostics."""

    stage: ProposalValidationStage
    detail_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.stage, ProposalValidationStage):
            raise TypeError("proposal failure stage must be ProposalValidationStage")
        _text(self.detail_code, "proposal failure detail_code")


@dataclass(frozen=True, slots=True)
class UnflattenAuthorityPreparationRejected:
    verdict: UnflattenAuthorityVerdict
    proposal_failure: "ProposalValidationFailure | None" = None

    def __post_init__(self) -> None:
        if type(self.verdict) is not UnflattenAuthorityVerdict or self.verdict.accepted:
            raise ValueError("preparation rejected requires a rejected verdict")
        if self.proposal_failure is not None and type(self.proposal_failure) is not ProposalValidationFailure:
            raise TypeError("proposal_failure must be ProposalValidationFailure or None")


UnflattenAuthorityPreparationResult: TypeAlias = (UnflattenAuthorityNotApplicable | UnflattenAuthorityPreparationAccepted | UnflattenAuthorityPreparationRejected)


@dataclass(frozen=True, slots=True)
class UnflattenAuthorityBindingAccepted:
    authority: BoundUnflattenAuthority

    def __post_init__(self) -> None:
        if type(self.authority) is not BoundUnflattenAuthority:
            raise TypeError("authority must be BoundUnflattenAuthority")


@dataclass(frozen=True, slots=True)
class UnflattenAuthorityBindingRejected:
    verdict: UnflattenAuthorityVerdict

    def __post_init__(self) -> None:
        if type(self.verdict) is not UnflattenAuthorityVerdict or self.verdict.accepted:
            raise ValueError("binding rejected requires a rejected verdict")


UnflattenAuthorityBindingResult: TypeAlias = UnflattenAuthorityBindingAccepted | UnflattenAuthorityBindingRejected


class RouteRealizationKind(str, Enum):
    DIRECT_REDIRECT = "direct_redirect"
    CONDITIONAL_REDIRECT = "conditional_redirect"
    HELPER_CORRIDOR = "helper_corridor"
    PRESERVED = "preserved"
    FOLDED = "folded"


class RouteRealizationFailureStage(str, Enum):
    SOURCE_AUTHORITY = "source_authority"
    CLAIM_COVERAGE = "claim_coverage"
    CLAIM_SELECTION = "claim_selection"
    PLAN_STEP_CORRELATION = "plan_step_correlation"
    OLD_EDGE_REMOVAL = "old_edge_removal"
    NEW_EDGE_REALIZATION = "new_edge_realization"
    CONDITIONAL_ROLES = "conditional_roles"
    HELPER_LINEAGE = "helper_lineage"
    EFFECT_TERMINAL_PRESERVATION = "effect_terminal_preservation"
    OBSERVED_LINEAGE = "observed_lineage"
    RETIREMENT_CORRELATION = "retirement_correlation"
    ATTEMPT_BINDING = "attempt_binding"
    UNSUPPORTED_REALIZATION_KIND = "unsupported_realization_kind"


class RouteRealizationFailureScope(str, Enum):
    PROPOSAL = "proposal"
    EVIDENCE = "evidence"
    CLAIM = "claim"
    STEP = "step"


@dataclass(frozen=True, slots=True)
class AnchoredBlockRef:
    ref: CfgBlockRef
    anchor_ea: int

    def __post_init__(self) -> None:
        _cfg_ref(self.ref, "anchored block ref")
        _ea(self.anchor_ea, "anchored block EA")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class EffectSiteCoordinate:
    """Serial-free identity for one observed effect instruction."""

    owner: AnchoredBlockRef
    instruction_ordinal: int
    instruction_ea: int
    effect_kind: EffectSiteKind
    opcode: int
    width: int

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("semantic site records are binder-owned")

    def __post_init__(self) -> None:
        if type(self.owner) is not AnchoredBlockRef:
            raise TypeError("effect site owner must be AnchoredBlockRef")
        self.owner.__post_init__()
        _nonnegative(self.instruction_ordinal, "effect site instruction_ordinal")
        _ea(self.instruction_ea, "effect site instruction_ea")
        _enum(self.effect_kind, EffectSiteKind, "effect site effect_kind")
        if type(self.opcode) is not int or isinstance(self.opcode, bool) or self.opcode < 0:
            raise ValueError("effect site opcode must be a non-negative exact int")
        _nonnegative(self.width, "effect site width")

    __copy__ = _reject_site_record_copy
    __deepcopy__ = _reject_site_record_copy
    __reduce__ = _reject_site_record_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class TerminalSiteCoordinate:
    """Serial-free identity for one observed terminal instruction."""

    owner: AnchoredBlockRef
    instruction_ordinal: int | None
    instruction_ea: int
    terminal_kind: TerminalKind

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("semantic site records are binder-owned")

    def __post_init__(self) -> None:
        if type(self.owner) is not AnchoredBlockRef:
            raise TypeError("terminal site owner must be AnchoredBlockRef")
        self.owner.__post_init__()
        _ea(self.instruction_ea, "terminal site instruction_ea")
        _enum(self.terminal_kind, TerminalKind, "terminal site terminal_kind")
        if self.instruction_ordinal is None:
            if self.terminal_kind is not TerminalKind.STOP:
                raise ValueError("only synthesized STOP terminals may omit ordinal")
        else:
            _nonnegative(self.instruction_ordinal, "terminal site instruction_ordinal")
            if self.terminal_kind is TerminalKind.STOP:
                raise ValueError("STOP terminal coordinates require ordinal None")

    __copy__ = _reject_site_record_copy
    __deepcopy__ = _reject_site_record_copy
    __reduce__ = _reject_site_record_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RawEffectGatePhaseFact:
    """Canonical SOURCE raw effect partition used before authority minting."""

    phase: UnflattenAuthorityPhase
    source_inventory_digest: str
    projected_inventory_digest: str
    source_fingerprint: str
    projected_fingerprint: str
    source_generation: int
    projected_generation: int
    pre_effectful_source_owners: tuple[AnchoredBlockRef, ...]
    raw_retained_source_owners: tuple[AnchoredBlockRef, ...]
    raw_lost_source_owners: tuple[AnchoredBlockRef, ...]
    generic_raw_payload_digest: str
    fact_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("raw effect gate phase facts are binder-owned")

    def __post_init__(self) -> None:
        if self.phase is not UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("raw effect gate fact must be projected-preflight")
        for name in (
            "source_inventory_digest", "projected_inventory_digest",
            "source_fingerprint", "projected_fingerprint",
            "generic_raw_payload_digest", "fact_id",
        ):
            _id(getattr(self, name), name)
        _generation(self.source_generation, "source_generation")
        _generation(self.projected_generation, "projected_generation")
        if type(self.pre_effectful_source_owners) is not tuple:
            raise TypeError("pre_effectful_source_owners must be an exact tuple")
        if type(self.raw_retained_source_owners) is not tuple:
            raise TypeError("raw_retained_source_owners must be an exact tuple")
        if type(self.raw_lost_source_owners) is not tuple:
            raise TypeError("raw_lost_source_owners must be an exact tuple")
        for name in (
            "pre_effectful_source_owners", "raw_retained_source_owners",
            "raw_lost_source_owners",
        ):
            owners = getattr(self, name)
            if any(type(item) is not AnchoredBlockRef for item in owners):
                raise TypeError(f"{name} must contain AnchoredBlockRef values")
            for item in owners:
                item.__post_init__()
            if owners != tuple(sorted(owners, key=canonical_bytes)):
                raise ValueError(f"{name} must be in canonical owner order")
            if len(set(owners)) != len(owners):
                raise ValueError(f"{name} must not contain duplicate owners")
        pre = set(self.pre_effectful_source_owners)
        retained = set(self.raw_retained_source_owners)
        lost = set(self.raw_lost_source_owners)
        if retained & lost or retained | lost != pre:
            raise ValueError("raw effect owners must form a complete disjoint partition")
        if self.fact_id != raw_effect_gate_phase_fact_id(self):
            raise ValueError("fact_id does not match canonical raw gate content")

    __copy__ = _reject_site_record_copy
    __deepcopy__ = _reject_site_record_copy
    __reduce__ = _reject_site_record_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ScalarizedInstructionCoordinate:
    owner: AnchoredBlockRef
    instruction_ordinal: int
    instruction_ea: int
    instruction_kind: Literal[InsnKind.MOV]
    opcode: int
    raw_opcode: int
    width: int
    display_text_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("semantic site records are binder-owned")

    def __post_init__(self) -> None:
        if type(self.owner) is not AnchoredBlockRef:
            raise TypeError("scalarized site owner must be AnchoredBlockRef")
        self.owner.__post_init__()
        _nonnegative(self.instruction_ordinal, "scalarized instruction ordinal")
        _ea(self.instruction_ea, "scalarized instruction EA")
        if self.instruction_kind is not InsnKind.MOV:
            raise ValueError("scalarized instruction must be MOV")
        for name in ("opcode", "raw_opcode", "width"):
            _nonnegative(getattr(self, name), f"scalarized {name}")
        _id(self.display_text_digest, "display_text_digest")

    __copy__ = _reject_site_record_copy
    __deepcopy__ = _reject_site_record_copy
    __reduce__ = _reject_site_record_copy


class ProjectedEffectSiteOutcome(str, Enum):
    PRESERVED = "preserved"
    RELATION_CLONED = "relation_cloned"
    EXACT_INFEASIBLE = "exact_infeasible"
    LOCAL_ALIAS_SCALARIZED = "local_alias_scalarized"
    # This is a sealed observation of a missing source effect, not an
    # allowance.  It deliberately reaches canonical case evaluation so the
    # transaction-owned ledger can classify and reject it atomically.
    UNCLASSIFIED = "unclassified"


class ProjectedTerminalSiteOutcome(str, Enum):
    PRESERVED = "preserved"
    RELATION_CLONED = "relation_cloned"


def _site_id(value: object, label: str) -> str:
    return _id(value, label)


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ExactEffectBindingResult:
    authority_id: str
    source_authority_id: str
    attempt_id: TransactionAttemptId
    phase: Literal[UnflattenAuthorityPhase.PROJECTED_PREFLIGHT]
    claim: ExactInfeasibleEffectClaim
    proof_id: str
    supporting_route_relation_id: str
    source_subject_ids: tuple[str, ...]
    source_site: EffectSiteCoordinate
    source_inventory_digest: str
    projected_inventory_digest: str
    source_fingerprint: str
    projected_fingerprint: str
    source_generation: int
    projected_generation: int
    raw_effect_gate_fact_id: str
    binding_result_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("exact-effect binding results are binder-owned")

    def __post_init__(self) -> None:
        for name in ("authority_id", "source_authority_id", "proof_id", "supporting_route_relation_id", "source_inventory_digest", "projected_inventory_digest", "source_fingerprint", "projected_fingerprint", "raw_effect_gate_fact_id", "binding_result_id"):
            _site_id(getattr(self, name), name)
        if type(self.attempt_id) is not TransactionAttemptId:
            raise TypeError("attempt_id must be TransactionAttemptId")
        self.attempt_id.__post_init__()
        if self.phase is not UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("exact-effect binding must be projected-preflight")
        if type(self.claim) is not ExactInfeasibleEffectClaim:
            raise TypeError("claim must be ExactInfeasibleEffectClaim")
        self.claim.__post_init__()
        if type(self.source_subject_ids) is not tuple or not self.source_subject_ids:
            raise TypeError("source_subject_ids must be a non-empty tuple")
        if any(not isinstance(item, str) for item in self.source_subject_ids) or self.source_subject_ids != tuple(sorted(set(self.source_subject_ids))):
            raise ValueError("source_subject_ids must be sorted and unique")
        if type(self.source_site) is not EffectSiteCoordinate:
            raise TypeError("source_site must be EffectSiteCoordinate")
        self.source_site.__post_init__()
        for name in ("source_generation", "projected_generation"):
            _generation(getattr(self, name), name)
        if self.binding_result_id != exact_effect_binding_result_id(self):
            raise ValueError("binding_result_id does not match exact-effect content")

    __copy__ = _reject_site_record_copy
    __deepcopy__ = _reject_site_record_copy
    __reduce__ = _reject_site_record_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class LocalAliasScalarizationBindingResult:
    authority_id: str
    attempt_id: TransactionAttemptId
    phase: Literal[UnflattenAuthorityPhase.PROJECTED_PREFLIGHT]
    claim: LocalAliasEffectScalarizationClaim
    source_subject_id: str
    source_site: EffectSiteCoordinate
    scalarized_site: ScalarizedInstructionCoordinate
    patch_step_fact: PatchStepEvidencePayload
    patch_step_fact_id: str
    source_inventory_digest: str
    projected_inventory_digest: str
    source_fingerprint: str
    projected_fingerprint: str
    source_generation: int
    projected_generation: int
    binding_result_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("local-alias binding results are binder-owned")

    def __post_init__(self) -> None:
        for name in ("authority_id", "source_subject_id", "patch_step_fact_id", "source_inventory_digest", "projected_inventory_digest", "source_fingerprint", "projected_fingerprint", "binding_result_id"):
            _site_id(getattr(self, name), name)
        if type(self.attempt_id) is not TransactionAttemptId:
            raise TypeError("attempt_id must be TransactionAttemptId")
        self.attempt_id.__post_init__()
        if self.phase is not UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("local-alias binding must be projected-preflight")
        if type(self.claim) is not LocalAliasEffectScalarizationClaim:
            raise TypeError("claim must be LocalAliasEffectScalarizationClaim")
        self.claim.__post_init__()
        _site_id(self.source_subject_id, "source_subject_id")
        if type(self.source_site) is not EffectSiteCoordinate or type(self.scalarized_site) is not ScalarizedInstructionCoordinate:
            raise TypeError("local-alias binding sites must be closed coordinates")
        self.source_site.__post_init__(); self.scalarized_site.__post_init__()
        if type(self.patch_step_fact) is not PatchStepEvidencePayload:
            raise TypeError("patch_step_fact must be PatchStepEvidencePayload")
        self.patch_step_fact.__post_init__()
        if self.patch_step_fact_id != _canonical_patch_step_fact_id(self.patch_step_fact):
            raise ValueError("patch_step_fact_id does not match payload")
        for name in ("source_generation", "projected_generation"):
            _generation(getattr(self, name), name)
        if self.binding_result_id != local_alias_binding_result_id(self):
            raise ValueError("binding_result_id does not match local-alias content")

    __copy__ = _reject_site_record_copy
    __deepcopy__ = _reject_site_record_copy
    __reduce__ = _reject_site_record_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ProjectedEffectSiteResult:
    authority_id: str; attempt_id: TransactionAttemptId; phase: Literal[UnflattenAuthorityPhase.PROJECTED_PREFLIGHT]
    source_subject_id: str; source_site: EffectSiteCoordinate; outcome: ProjectedEffectSiteOutcome
    projected_subject_id: str | None; projected_site: EffectSiteCoordinate | None
    scalarized_site: ScalarizedInstructionCoordinate | None; lineage_kind: ProjectedSiteLineageKind | None
    relation_id: str | None; supporting_claim_id: str | None; supporting_binding_result_id: str | None
    latent_exact_binding_result_id: str | None; patch_step_index: int | None; patch_step_digest: str | None
    raw_effect_gate_fact_id: str; result_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("projected effect site results are binder-owned")

    def __post_init__(self) -> None:
        for name in ("authority_id", "source_subject_id", "raw_effect_gate_fact_id", "result_id"):
            _site_id(getattr(self, name), name)
        if type(self.attempt_id) is not TransactionAttemptId: raise TypeError("attempt_id must be TransactionAttemptId")
        self.attempt_id.__post_init__(); _enum(self.outcome, ProjectedEffectSiteOutcome, "outcome")
        if type(self.source_site) is not EffectSiteCoordinate: raise TypeError("source_site must be EffectSiteCoordinate")
        self.source_site.__post_init__()
        for name in ("projected_subject_id", "relation_id", "supporting_claim_id", "supporting_binding_result_id", "latent_exact_binding_result_id", "patch_step_digest"):
            value = getattr(self, name)
            if value is not None: _site_id(value, name)
        if self.patch_step_index is not None: _nonnegative(self.patch_step_index, "patch_step_index")
        if self.projected_site is not None:
            if type(self.projected_site) is not EffectSiteCoordinate: raise TypeError("projected_site must be EffectSiteCoordinate")
            self.projected_site.__post_init__()
        if self.scalarized_site is not None:
            if type(self.scalarized_site) is not ScalarizedInstructionCoordinate: raise TypeError("scalarized_site must be ScalarizedInstructionCoordinate")
            self.scalarized_site.__post_init__()
        if self.lineage_kind is not None: _enum(self.lineage_kind, ProjectedSiteLineageKind, "lineage_kind")
        if self.outcome in (ProjectedEffectSiteOutcome.PRESERVED, ProjectedEffectSiteOutcome.RELATION_CLONED):
            if self.projected_site is None or self.lineage_kind is None or self.projected_subject_id is None: raise ValueError("preserved effect requires projected site and lineage")
            if self.outcome is ProjectedEffectSiteOutcome.PRESERVED and self.lineage_kind is not ProjectedSiteLineageKind.SAME_OWNER: raise ValueError("preserved effect requires same-owner lineage")
            if self.outcome is ProjectedEffectSiteOutcome.RELATION_CLONED and self.lineage_kind is not ProjectedSiteLineageKind.RELATION_CLONE: raise ValueError("cloned effect requires relation-clone lineage")
            if self.outcome is ProjectedEffectSiteOutcome.PRESERVED and self.relation_id is not None: raise ValueError("preserved effect cannot carry relation lineage")
            if self.outcome is ProjectedEffectSiteOutcome.RELATION_CLONED and self.relation_id is None: raise ValueError("cloned effect requires relation ID")
            if self.outcome is ProjectedEffectSiteOutcome.RELATION_CLONED and self.source_subject_id == self.projected_subject_id: raise ValueError("cloned effect subjects must be distinct")
            if self.scalarized_site is not None or self.supporting_claim_id is not None or self.supporting_binding_result_id is not None or self.patch_step_index is not None or self.patch_step_digest is not None: raise ValueError("preserved effect cannot carry active binding")
        elif self.outcome is ProjectedEffectSiteOutcome.EXACT_INFEASIBLE:
            if self.projected_subject_id is not None or self.projected_site is not None or self.scalarized_site is not None or self.supporting_claim_id is None or self.supporting_binding_result_id is None: raise ValueError("exact infeasible effect requires active binding and no projected site")
            if self.lineage_kind is not None or self.relation_id is not None or self.latent_exact_binding_result_id is not None: raise ValueError("exact infeasible effect has no lineage or latent binding")
            if self.patch_step_index is not None or self.patch_step_digest is not None: raise ValueError("exact infeasible effect has no patch step")
        elif self.outcome is ProjectedEffectSiteOutcome.LOCAL_ALIAS_SCALARIZED:
            if self.projected_subject_id is not None or self.projected_site is not None or self.scalarized_site is None or self.supporting_claim_id is None or self.supporting_binding_result_id is None or self.patch_step_index is None or self.patch_step_digest is None: raise ValueError("scalarized effect requires exact scalar binding")
            if self.lineage_kind is not None or self.relation_id is not None or self.latent_exact_binding_result_id is not None: raise ValueError("scalarized effect has no lineage or latent exact binding")
        else:
            if (
                self.projected_subject_id is not None
                or self.projected_site is not None
                or self.scalarized_site is not None
                or self.lineage_kind is not None
                or self.relation_id is not None
                or self.supporting_claim_id is not None
                or self.supporting_binding_result_id is not None
                or self.latent_exact_binding_result_id is not None
                or self.patch_step_index is not None
                or self.patch_step_digest is not None
            ):
                raise ValueError("unclassified effect must retain only its exact missing source site")
        if self.result_id != projected_effect_site_result_id(self): raise ValueError("result_id does not match effect site content")
    __copy__ = _reject_site_record_copy; __deepcopy__ = _reject_site_record_copy; __reduce__ = _reject_site_record_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ProjectedTerminalSiteResult:
    authority_id: str; attempt_id: TransactionAttemptId; phase: Literal[UnflattenAuthorityPhase.PROJECTED_PREFLIGHT]
    source_subject_id: str; source_site: TerminalSiteCoordinate; outcome: ProjectedTerminalSiteOutcome
    projected_subject_id: str; projected_site: TerminalSiteCoordinate; lineage_kind: ProjectedSiteLineageKind
    relation_id: str | None; result_id: str
    def __init__(self, *args: object, **kwargs: object) -> None: del args, kwargs; raise TypeError("projected terminal site results are binder-owned")
    def __post_init__(self) -> None:
        for name in ("authority_id", "source_subject_id", "projected_subject_id", "result_id"): _site_id(getattr(self, name), name)
        if type(self.attempt_id) is not TransactionAttemptId: raise TypeError("attempt_id must be TransactionAttemptId")
        self.attempt_id.__post_init__(); _enum(self.phase, UnflattenAuthorityPhase, "phase"); _enum(self.outcome, ProjectedTerminalSiteOutcome, "outcome"); _enum(self.lineage_kind, ProjectedSiteLineageKind, "lineage_kind")
        if type(self.source_site) is not TerminalSiteCoordinate or type(self.projected_site) is not TerminalSiteCoordinate: raise TypeError("terminal sites must be TerminalSiteCoordinate")
        self.source_site.__post_init__(); self.projected_site.__post_init__()
        if self.outcome is ProjectedTerminalSiteOutcome.PRESERVED and self.lineage_kind is not ProjectedSiteLineageKind.SAME_OWNER: raise ValueError("preserved terminal requires same-owner lineage")
        if self.outcome is ProjectedTerminalSiteOutcome.PRESERVED and self.relation_id is not None: raise ValueError("preserved terminal cannot carry relation lineage")
        if self.outcome is ProjectedTerminalSiteOutcome.RELATION_CLONED and (self.lineage_kind is not ProjectedSiteLineageKind.RELATION_CLONE or self.relation_id is None): raise ValueError("cloned terminal requires relation lineage")
        if self.result_id != projected_terminal_site_result_id(self): raise ValueError("result_id does not match terminal site content")
    __copy__ = _reject_site_record_copy; __deepcopy__ = _reject_site_record_copy; __reduce__ = _reject_site_record_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ProjectedSemanticSitePhaseResult:
    authority_id: str
    source_authority_id: str
    attempt_id: TransactionAttemptId
    phase: Literal[UnflattenAuthorityPhase.PROJECTED_PREFLIGHT]
    plan_id: str
    source_inventory_digest: str
    projected_inventory_digest: str
    source_fingerprint: str
    projected_fingerprint: str
    source_generation: int
    projected_generation: int
    relation_ids: tuple[str, ...]
    raw_effect_gate_fact: RawEffectGatePhaseFact
    exact_effect_bindings: tuple[ExactEffectBindingResult, ...]
    local_alias_bindings: tuple[LocalAliasScalarizationBindingResult, ...]
    effect_results: tuple[ProjectedEffectSiteResult, ...]
    terminal_results: tuple[ProjectedTerminalSiteResult, ...]
    derived_effect_gate_fact_id: str
    result_id: str

    def __init__(self, *args: object, **kwargs: object) -> None: del args, kwargs; raise TypeError("projected site phase results are binder-owned")
    def __post_init__(self) -> None:
        for name in ("authority_id", "source_authority_id", "plan_id", "source_inventory_digest", "projected_inventory_digest", "source_fingerprint", "projected_fingerprint", "derived_effect_gate_fact_id", "result_id"):
            _site_id(getattr(self, name), name)
        if type(self.attempt_id) is not TransactionAttemptId: raise TypeError("attempt_id must be TransactionAttemptId")
        self.attempt_id.__post_init__()
        if self.phase is not UnflattenAuthorityPhase.PROJECTED_PREFLIGHT: raise ValueError("site phase must be projected-preflight")
        _generation(self.source_generation, "source_generation"); _generation(self.projected_generation, "projected_generation")
        if type(self.relation_ids) is not tuple or self.relation_ids != tuple(sorted(set(self.relation_ids))): raise ValueError("relation_ids must be sorted and unique")
        for item in self.relation_ids: _site_id(item, "relation_id")
        if type(self.raw_effect_gate_fact) is not RawEffectGatePhaseFact: raise TypeError("raw_effect_gate_fact must be RawEffectGatePhaseFact")
        self.raw_effect_gate_fact.__post_init__()
        for name, typ in (("exact_effect_bindings", ExactEffectBindingResult), ("local_alias_bindings", LocalAliasScalarizationBindingResult), ("effect_results", ProjectedEffectSiteResult), ("terminal_results", ProjectedTerminalSiteResult)):
            values = getattr(self, name)
            if type(values) is not tuple or any(type(item) is not typ for item in values): raise TypeError(f"{name} must contain exact closed records")
            ids = tuple(getattr(item, "binding_result_id", getattr(item, "result_id", "")) for item in values)
            if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids): raise ValueError(f"{name} must be sorted and unique")
            for item in values: item.__post_init__()
        if any(item.authority_id != self.authority_id or item.attempt_id is not self.attempt_id for item in (*self.exact_effect_bindings, *self.local_alias_bindings, *self.effect_results, *self.terminal_results)):
            raise ValueError("site results must carry the exact aggregate authority and attempt")
        for item in (*self.exact_effect_bindings, *self.local_alias_bindings):
            if item.source_inventory_digest != self.source_inventory_digest or item.projected_inventory_digest != self.projected_inventory_digest or item.source_fingerprint != self.source_fingerprint or item.projected_fingerprint != self.projected_fingerprint or item.source_generation != self.source_generation or item.projected_generation != self.projected_generation:
                raise ValueError("site result inventory envelope differs from aggregate")
        if any(item.raw_effect_gate_fact_id != self.raw_effect_gate_fact.fact_id for item in self.effect_results):
            raise ValueError("effect rows must cite the aggregate raw gate fact")
        exact_ids = {item.binding_result_id for item in self.exact_effect_bindings}
        exact_refs = {
            item.supporting_binding_result_id or item.latent_exact_binding_result_id
            for item in self.effect_results
            if item.supporting_binding_result_id in exact_ids or item.latent_exact_binding_result_id in exact_ids
        }
        exact_ref_values = tuple(
            item.supporting_binding_result_id or item.latent_exact_binding_result_id
            for item in self.effect_results
            if (item.supporting_binding_result_id or item.latent_exact_binding_result_id) in exact_ids
        )
        if exact_refs != exact_ids or len(exact_ref_values) != len(exact_ids) or len(set(exact_ref_values)) != len(exact_ref_values):
            raise ValueError("every exact-effect binding must be referenced exactly once")
        alias_ids = {item.binding_result_id for item in self.local_alias_bindings}
        alias_refs = {item.supporting_binding_result_id for item in self.effect_results if item.supporting_binding_result_id in alias_ids}
        if alias_refs != alias_ids or any(item.supporting_binding_result_id in alias_ids and item.outcome is not ProjectedEffectSiteOutcome.LOCAL_ALIAS_SCALARIZED for item in self.effect_results):
            raise ValueError("every local-alias binding must be the active support of one scalarized row")
        if len({item.source_subject_id for item in self.effect_results}) != len(self.effect_results):
            raise ValueError("effect site results must cover unique source subjects")
        if len({item.source_subject_id for item in self.terminal_results}) != len(self.terminal_results):
            raise ValueError("terminal site results must cover unique source subjects")
        expected_derived = derived_effect_gate_fact_id(self.raw_effect_gate_fact.fact_id, tuple(item.result_id for item in self.effect_results))
        if self.derived_effect_gate_fact_id != expected_derived: raise ValueError("derived effect gate fact ID mismatch")
        if self.result_id != projected_semantic_site_phase_result_id(self): raise ValueError("site phase result ID mismatch")
    __copy__ = _reject_site_record_copy; __deepcopy__ = _reject_site_record_copy; __reduce__ = _reject_site_record_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ProjectedRouteSitePreservation:
    authority_id: str
    attempt_id: TransactionAttemptId
    relation_id: str
    site_phase_result_id: str
    effect_result_ids: tuple[str, ...]
    terminal_result_ids: tuple[str, ...]
    preservation_id: str
    def __init__(self, *args: object, **kwargs: object) -> None: del args, kwargs; raise TypeError("route site preservation records are binder-owned")
    def __post_init__(self) -> None:
        for name in ("authority_id", "relation_id", "site_phase_result_id", "preservation_id"): _site_id(getattr(self, name), name)
        if type(self.attempt_id) is not TransactionAttemptId: raise TypeError("attempt_id must be TransactionAttemptId")
        self.attempt_id.__post_init__()
        for name in ("effect_result_ids", "terminal_result_ids"):
            values = getattr(self, name)
            if type(values) is not tuple or values != tuple(sorted(set(values))): raise ValueError(f"{name} must be sorted and unique")
            for item in values: _site_id(item, f"{name} item")
        if self.preservation_id != projected_route_site_preservation_id(self): raise ValueError("preservation ID mismatch")
    __copy__ = _reject_site_record_copy; __deepcopy__ = _reject_site_record_copy; __reduce__ = _reject_site_record_copy


def _route_refs(values: Iterable[object], label: str) -> tuple[CfgBlockRef, ...]:
    refs = tuple(values)
    if len(set(refs)) != len(refs):
        raise ValueError(f"{label} must not contain duplicates")
    for ref in refs:
        _cfg_ref(ref, f"{label} item")
    return tuple(sorted(refs, key=canonical_bytes))


@dataclass(frozen=True, slots=True)
class ConditionalRoleCoordinate:
    role: SemanticEdgeRole
    coordinate: int

    def __post_init__(self) -> None:
        _enum(self.role, SemanticEdgeRole, "conditional role")
        _nonnegative(self.coordinate, "conditional role coordinate")


@dataclass(frozen=True, slots=True)
class RealizedConditionalArm:
    role: SemanticEdgeRole
    target: AnchoredBlockRef

    def __post_init__(self) -> None:
        _enum(self.role, SemanticEdgeRole, "conditional arm role")
        if type(self.target) is not AnchoredBlockRef:
            raise TypeError("conditional arm target must be AnchoredBlockRef")
        self.target.__post_init__()


def _reject_route_copy(self, *args: object) -> None:
    del self, args
    raise TypeError("route authority records are transaction-owned")


def _validate_route_anchor(value: AnchoredBlockRef, label: str) -> None:
    if type(value) is not AnchoredBlockRef:
        raise TypeError(f"{label} must be AnchoredBlockRef")
    value.__post_init__()
    if type(value.ref) is NativeBlockRef and not value.ref.identity.native_ranges.contains(value.anchor_ea):
        raise ValueError(f"{label} anchor is outside native identity range")


def _validate_route_ref_coherence(values: tuple[AnchoredBlockRef, ...]) -> None:
    for index, value in enumerate(values):
        _validate_route_anchor(value, f"route coordinate {index}")
    native_keys = {
        value.ref.identity.native_key for value in values
        if type(value.ref) is NativeBlockRef
    }
    if len(native_keys) > 1:
        raise ValueError("route native references must share one native key")
    sessions = {
        value.ref.session_id for value in values
        if type(value.ref) is LogicalBlockRef
    }
    if len(sessions) > 1:
        raise ValueError("route logical references must share one session")
    plans = {
        value.ref.plan_id for value in values
        if type(value.ref) is PlanBlockRef
    }
    if len(plans) > 1:
        raise ValueError("route plan references must share one plan")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RouteRealizationFailure:
    claim_id: str | None
    proof_id: str | None
    route_subject_id: str | None
    scope: RouteRealizationFailureScope
    proposal_id: str | None
    evidence_id: str | None
    stage: RouteRealizationFailureStage
    step_index: int | None
    step_digest: str | None
    anchored_refs: tuple[AnchoredBlockRef, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("route realization failures are binder-owned")

    def __post_init__(self) -> None:
        for name in ("claim_id", "proof_id", "route_subject_id", "proposal_id", "evidence_id"):
            value = getattr(self, name)
            if value is not None:
                _id(value, f"failure {name}")
        _enum(self.scope, RouteRealizationFailureScope, "failure scope")
        _enum(self.stage, RouteRealizationFailureStage, "failure stage")
        if self.step_index is not None:
            _nonnegative(self.step_index, "failure step_index")
        if self.step_digest is not None:
            _id(self.step_digest, "failure step_digest")
        refs = tuple(self.anchored_refs)
        if any(type(item) is not AnchoredBlockRef for item in refs): raise TypeError("failure anchored_refs must be AnchoredBlockRef values")
        if len(set(refs)) != len(refs): raise ValueError("failure anchored_refs must not contain duplicates")
        object.__setattr__(self, "anchored_refs", tuple(sorted(refs, key=canonical_bytes)))

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class SourceBoundRouteAuthority:
    phase: UnflattenAuthorityPhase
    proposal: ProposedUnflattenContract
    proposal_id: str
    plan_id: str
    source_native_key: NativePreanalysisKey
    source_fingerprint: str
    source_inventory_digest: str
    source_generation: int
    evidence_id: str
    bound_evidence: BoundCanonicalSemanticEvidence
    covered_proof_ids: tuple[str, ...]
    covered_claim_ids: tuple[str, ...]
    source_authority_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("source route authority is transaction-owned")

    def __post_init__(self) -> None:
        if self.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("source route authority is source-only")
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("proposal must be ProposedUnflattenContract")
        self.proposal.__post_init__()
        if type(self.bound_evidence) is not BoundCanonicalSemanticEvidence:
            raise TypeError("bound_evidence must be BoundCanonicalSemanticEvidence")
        if self.bound_evidence.evidence != self.proposal.route_evidence:
            raise ValueError("bound evidence does not match proposal evidence")
        _id(self.proposal_id, "proposal_id")
        if self.proposal_id != authority_id(self.proposal):
            raise ValueError("proposal_id is not content-derived")
        _id(self.plan_id, "plan_id")
        if self.plan_id != self.proposal.plan_id:
            raise ValueError("source authority plan differs from proposal")
        if self.source_native_key != self.proposal.source_identity_catalog.native_key:
            raise ValueError("source native key differs from proposal")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.source_inventory_digest, "source_inventory_digest")
        _generation(self.source_generation)
        if self.source_generation != self.proposal.source_identity_catalog.generation:
            raise ValueError("source generation differs from proposal")
        _id(self.evidence_id, "evidence_id")
        if self.evidence_id != self.proposal.route_evidence.atomic_group_id:
            raise ValueError("source evidence differs from proposal")
        proof_ids = tuple(sorted(proof.proof_id for proof in self.proposal.route_evidence.route_proofs))
        if self.covered_proof_ids != proof_ids:
            raise ValueError("source authority must cover the complete proof group")
        claim_ids = tuple(sorted(claim.claim_id for claim in self.proposal.claims if type(claim) is EquivalentSemanticRouteClaim))
        if self.covered_claim_ids != claim_ids:
            raise ValueError("source authority must cover the complete route claim set")
        if len(self.bound_evidence.routes) != len(proof_ids) or tuple(sorted(route.evidence.proof_id for route in self.bound_evidence.routes)) != proof_ids:
            raise ValueError("bound evidence must contain every proof exactly once")
        expected = source_route_authority_id((self.phase, self.proposal_id, self.plan_id,
            self.source_native_key, self.source_fingerprint, self.source_inventory_digest,
            self.source_generation, self.evidence_id, self.bound_evidence,
            self.covered_proof_ids, self.covered_claim_ids))
        if self.source_authority_id != expected:
            raise ValueError("source_authority_id does not match canonical content")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class DirectRouteRealization:
    feeder: AnchoredBlockRef
    old_target: AnchoredBlockRef
    new_target: AnchoredBlockRef
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("direct route realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (self.feeder, self.old_target, self.new_target)
        _validate_route_ref_coherence(refs)
        if self.old_target.ref == self.new_target.ref:
            raise ValueError("direct route old and new targets must differ")
        _id(self.relation_id, "relation_id")
        expected = route_realization_id(("direct", self.feeder, self.old_target, self.new_target))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match direct route content")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class SharedCarrierSourceBypassRouteRealization:
    """One source-specific bypass of an exactly shared state-carrier feeder.

    The carrier feeder remains live for its other predecessors.  This relation
    therefore names both the semantic proof source and the shared physical
    carrier corridor instead of pretending the source-owned redirect is the
    ordinary feeder-owned direct realization.
    """

    proof_source: AnchoredBlockRef
    shared_feeder: AnchoredBlockRef
    comparison_entry: AnchoredBlockRef
    semantic_target: AnchoredBlockRef
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("shared-carrier source-bypass realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (
            self.proof_source,
            self.shared_feeder,
            self.comparison_entry,
            self.semantic_target,
        )
        _validate_route_ref_coherence(refs)
        if len({item.ref for item in refs}) != 4:
            raise ValueError("shared-carrier source-bypass roles must be distinct")
        _id(self.relation_id, "relation_id")
        expected = route_realization_id((
            "shared_carrier_source_bypass",
            self.proof_source,
            self.shared_feeder,
            self.comparison_entry,
            self.semantic_target,
        ))
        if self.relation_id != expected:
            raise ValueError(
                "relation_id does not match shared-carrier source-bypass content"
            )

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RetainedPrefixRouteRealization:
    """One preserved proof-source edge followed by a rewritten delivery edge.

    Some state writes must retain their single-successor carrier/glue block so
    its non-state semantics still execute.  The physical patch therefore owns
    the delivery block's outgoing edge, while the canonical proof remains
    anchored at its predecessor state write.  Keep both roles explicit instead
    of pretending either block owns the whole relation.
    """

    proof_source: AnchoredBlockRef
    delivery_owner: AnchoredBlockRef
    old_target: AnchoredBlockRef
    new_target: AnchoredBlockRef
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("retained-prefix route realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (
            self.proof_source,
            self.delivery_owner,
            self.old_target,
            self.new_target,
        )
        _validate_route_ref_coherence(refs)
        if self.proof_source.ref == self.delivery_owner.ref:
            raise ValueError("retained-prefix proof source and delivery owner must differ")
        if self.old_target.ref == self.new_target.ref:
            raise ValueError("retained-prefix old and new targets must differ")
        _id(self.relation_id, "relation_id")
        expected = route_realization_id((
            "retained_prefix",
            self.proof_source,
            self.delivery_owner,
            self.old_target,
            self.new_target,
        ))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match retained-prefix content")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class LoweredConditionalRouteRealization:
    feeder: AnchoredBlockRef
    proof_source: AnchoredBlockRef
    old_target: AnchoredBlockRef
    arms: tuple[RealizedConditionalArm, RealizedConditionalArm]
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("lowered conditional realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (self.feeder, self.proof_source, self.old_target, *(arm.target for arm in self.arms))
        _validate_route_ref_coherence(refs)
        arms = tuple(self.arms)
        if len(arms) != 2 or any(type(item) is not RealizedConditionalArm for item in arms):
            raise ValueError("conditional realization requires exactly two typed arms")
        if {item.role for item in arms} != {
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }:
            raise ValueError("conditional realization requires taken and fallthrough arms")
        if len({item.target.ref for item in arms}) != 2:
            raise ValueError("conditional arms must have distinct targets")
        object.__setattr__(self, "arms", tuple(sorted(arms, key=lambda item: item.role.value)))
        _id(self.relation_id, "relation_id")
        expected = route_realization_id(("lowered_conditional", self.feeder, self.proof_source, self.old_target, self.arms))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match conditional route content")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ClonedConditionalRouteRealization:
    feeder: AnchoredBlockRef
    proof_source: AnchoredBlockRef
    old_target: AnchoredBlockRef
    replacement_clone: AnchoredBlockRef
    fallthrough_helper: AnchoredBlockRef
    arms: tuple[RealizedConditionalArm, RealizedConditionalArm]
    creation_spec_digests: tuple[tuple[PlanBlockRef, str], ...]
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("cloned conditional realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (
            self.feeder, self.proof_source, self.old_target,
            self.replacement_clone, self.fallthrough_helper,
            *(arm.target for arm in self.arms),
        )
        _validate_route_ref_coherence(refs)
        if self.proof_source != self.old_target:
            raise ValueError("cloned conditional proof source and old target differ")
        if self.replacement_clone.ref == self.fallthrough_helper.ref:
            raise ValueError("cloned conditional clone and helper must differ")
        if type(self.replacement_clone.ref) is not PlanBlockRef or type(self.fallthrough_helper.ref) is not PlanBlockRef:
            raise TypeError("cloned conditional replacement refs must be PlanBlockRef")
        arms = tuple(self.arms)
        if len(arms) != 2 or any(type(item) is not RealizedConditionalArm for item in arms):
            raise ValueError("cloned conditional realization requires exactly two typed arms")
        if {item.role for item in arms} != {
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }:
            raise ValueError("cloned conditional realization requires taken and fallthrough arms")
        if len({item.target.ref for item in arms}) != 2:
            raise ValueError("cloned conditional arms must have distinct targets")
        object.__setattr__(self, "arms", tuple(sorted(arms, key=lambda item: item.role.value)))
        digests = tuple(self.creation_spec_digests)
        if len(digests) != 2:
            raise ValueError("cloned conditional realization requires two creation digests")
        if any(type(item) is not tuple or len(item) != 2 for item in digests):
            raise TypeError("creation_spec_digests must contain (PlanBlockRef, digest) pairs")
        if any(type(ref) is not PlanBlockRef for ref, _digest in digests):
            raise TypeError("creation_spec_digests refs must be PlanBlockRef")
        if any(type(digest) is not str or not digest.startswith("sha256:") for _ref, digest in digests):
            raise ValueError("creation_spec_digests must contain authority IDs")
        if {ref for ref, _digest in digests} != {self.replacement_clone.ref, self.fallthrough_helper.ref}:
            raise ValueError("creation digests must cover clone and helper exactly")
        if len({ref for ref, _digest in digests}) != 2:
            raise ValueError("creation digests must be distinct")
        if tuple(ref for ref, _digest in digests) != (
            self.replacement_clone.ref, self.fallthrough_helper.ref,
        ):
            raise ValueError("creation digests must follow clone/helper plan order")
        object.__setattr__(self, "creation_spec_digests", digests)
        _id(self.relation_id, "relation_id")
        expected = route_realization_id((
            "cloned_conditional", self.feeder, self.proof_source, self.old_target,
            self.replacement_clone, self.fallthrough_helper, self.arms,
            self.creation_spec_digests,
        ))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match cloned conditional content")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


def _validate_creation_spec_rows(
    rows: tuple[tuple[PlanBlockRef, str], ...], owners: tuple[PlanBlockRef, ...],
) -> tuple[tuple[PlanBlockRef, str], ...]:
    if type(rows) is not tuple:
        raise TypeError("creation_spec_digests must be an exact tuple")
    if len(rows) != len(owners):
        raise ValueError("creation_spec_digests must cover every created owner")
    for index, row in enumerate(rows):
        if type(row) is not tuple or len(row) != 2:
            raise TypeError("creation_spec_digests must contain pairs")
        ref, digest = row
        if type(ref) is not PlanBlockRef or ref != owners[index]:
            raise ValueError("creation_spec_digests must follow owner order")
        _id(digest, "creation spec digest")
    return rows


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ClonedSemanticInstructionOrigin:
    source_owner: AnchoredBlockRef
    clone_owner: AnchoredBlockRef
    source_ordinal: int
    projected_ordinal: int
    instruction_ea: int | None
    observation_digest: str
    origin_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("cloned semantic origins are binder-owned")

    def __post_init__(self) -> None:
        if type(self) is not ClonedSemanticInstructionOrigin:
            raise TypeError("cloned semantic origins are exact closed records")
        _validate_route_anchor(self.source_owner, "source_owner")
        _validate_route_anchor(self.clone_owner, "clone_owner")
        _nonnegative(self.source_ordinal, "source_ordinal")
        _nonnegative(self.projected_ordinal, "projected_ordinal")
        if self.instruction_ea is not None:
            _ea(self.instruction_ea, "instruction_ea")
        _id(self.observation_digest, "observation_digest")
        _id(self.origin_id, "origin_id")
        expected = cloned_semantic_instruction_origin_id((
            "cloned_semantic_instruction_origin", self.source_owner,
            self.clone_owner, self.source_ordinal, self.projected_ordinal,
            self.instruction_ea, self.observation_digest,
        ))
        if self.origin_id != expected:
            raise ValueError("origin_id does not match cloned semantic origin")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ClonedSemanticPrefix:
    ordinal: int
    source_owner: AnchoredBlockRef
    clone_owner: AnchoredBlockRef
    source_start_ordinal: int
    source_end_ordinal_exclusive: int
    instruction_origins: tuple[ClonedSemanticInstructionOrigin, ...]
    source_trailing_goto_ordinal: int
    projected_synthetic_goto_ordinal: int
    projected_successor: AnchoredBlockRef
    creation_spec_row: tuple[PlanBlockRef, str]
    prefix_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("cloned semantic prefixes are binder-owned")

    def __post_init__(self) -> None:
        if type(self) is not ClonedSemanticPrefix:
            raise TypeError("cloned semantic prefixes are exact closed records")
        _nonnegative(self.ordinal, "prefix ordinal")
        _validate_route_anchor(self.source_owner, "prefix source_owner")
        _validate_route_anchor(self.clone_owner, "prefix clone_owner")
        if type(self.instruction_origins) is not tuple:
            raise TypeError("instruction_origins must be an exact tuple")
        if any(type(origin) is not ClonedSemanticInstructionOrigin for origin in self.instruction_origins):
            raise TypeError("instruction_origins must contain exact origins")
        _nonnegative(self.source_start_ordinal, "source_start_ordinal")
        _nonnegative(self.source_end_ordinal_exclusive, "source_end_ordinal_exclusive")
        _nonnegative(self.source_trailing_goto_ordinal, "source_trailing_goto_ordinal")
        _nonnegative(self.projected_synthetic_goto_ordinal, "projected_synthetic_goto_ordinal")
        if self.source_start_ordinal != 0:
            raise ValueError("cloned semantic prefixes must start at ordinal zero")
        length = self.source_end_ordinal_exclusive
        if length != len(self.instruction_origins):
            raise ValueError("prefix end ordinal must equal origin count")
        if self.source_trailing_goto_ordinal != length or self.projected_synthetic_goto_ordinal != length:
            raise ValueError("prefix trailing GOTO ordinals must equal prefix length")
        _validate_route_anchor(self.projected_successor, "prefix projected_successor")
        if type(self.creation_spec_row) is not tuple or len(self.creation_spec_row) != 2:
            raise TypeError("creation_spec_row must be a (PlanBlockRef, digest) pair")
        creation_ref, creation_digest = self.creation_spec_row
        if type(creation_ref) is not PlanBlockRef or creation_ref != self.clone_owner.ref:
            raise ValueError("prefix creation owner differs from clone owner")
        _id(creation_digest, "prefix creation digest")
        for ordinal, origin in enumerate(self.instruction_origins):
            if (
                origin.source_owner != self.source_owner
                or origin.clone_owner != self.clone_owner
                or origin.source_ordinal != ordinal
                or origin.projected_ordinal != ordinal
            ):
                raise ValueError("prefix origins do not follow exact owner/ordinal order")
        _id(self.prefix_id, "prefix_id")
        expected = cloned_semantic_prefix_id((
            "cloned_semantic_prefix", self.ordinal, self.source_owner,
            self.clone_owner, self.source_start_ordinal,
            self.source_end_ordinal_exclusive, self.instruction_origins,
            self.source_trailing_goto_ordinal,
            self.projected_synthetic_goto_ordinal, self.projected_successor,
            self.creation_spec_row,
        ))
        if self.prefix_id != expected:
            raise ValueError("prefix_id does not match cloned semantic prefix")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class FoldedConditionalRouteRealization:
    """One exact two-arm conditional folded to its selected existing arm."""

    feeder: AnchoredBlockRef
    selected_target: AnchoredBlockRef
    discarded_target: AnchoredBlockRef
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("folded conditional realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (self.feeder, self.selected_target, self.discarded_target)
        _validate_route_ref_coherence(refs)
        if len({item.ref for item in refs}) != 3:
            raise ValueError("folded conditional roles must be distinct")
        _id(self.relation_id, "relation_id")
        expected = route_realization_id((
            "folded_conditional", self.feeder,
            self.selected_target, self.discarded_target,
        ))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match folded conditional")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class TwoArmDirectBranchRouteRealization:
    feeder: AnchoredBlockRef
    source_rewritten_arm: AnchoredBlockRef
    projected_replacement_arm: AnchoredBlockRef
    untouched_arm: AnchoredBlockRef
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("two-arm branch realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (self.feeder, self.source_rewritten_arm, self.projected_replacement_arm, self.untouched_arm)
        _validate_route_ref_coherence(refs)
        if self.source_rewritten_arm.ref == self.projected_replacement_arm.ref:
            raise ValueError("branch source and projected arms must differ")
        _id(self.relation_id, "relation_id")
        expected = route_realization_id((
            "two_arm_direct_branch", self.feeder, self.source_rewritten_arm,
            self.projected_replacement_arm, self.untouched_arm,
        ))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match two-arm branch")

    __copy__ = _reject_route_copy; __deepcopy__ = _reject_route_copy; __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class BranchFallthroughHelperRouteRealization:
    feeder: AnchoredBlockRef
    source_fallthrough: AnchoredBlockRef
    untouched_conditional_arm: AnchoredBlockRef
    helper: AnchoredBlockRef
    semantic_target: AnchoredBlockRef
    creation_spec_digests: tuple[tuple[PlanBlockRef, str], ...]
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("branch helper realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (self.feeder, self.source_fallthrough, self.untouched_conditional_arm, self.helper, self.semantic_target)
        _validate_route_ref_coherence(refs)
        if type(self.helper.ref) is not PlanBlockRef:
            raise TypeError("branch helper must be a planned block")
        _validate_creation_spec_rows(self.creation_spec_digests, (self.helper.ref,))
        _id(self.relation_id, "relation_id")
        expected = route_realization_id((
            "branch_fallthrough_helper", self.feeder, self.source_fallthrough,
            self.untouched_conditional_arm, self.helper, self.semantic_target,
            self.creation_spec_digests,
        ))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match branch helper")

    __copy__ = _reject_route_copy; __deepcopy__ = _reject_route_copy; __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ClonedRouteCorridorRealization:
    predecessor: AnchoredBlockRef
    proof_source: AnchoredBlockRef
    descriptor_old_target: AnchoredBlockRef
    terminal_continuation: AnchoredBlockRef
    source_corridor: tuple[AnchoredBlockRef, ...]
    cloned_corridor: tuple[AnchoredBlockRef, ...]
    semantic_target: AnchoredBlockRef
    semantic_prefixes: tuple[ClonedSemanticPrefix, ...]
    creation_spec_digests: tuple[tuple[PlanBlockRef, str], ...]
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("route corridor realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (self.predecessor, self.proof_source, self.descriptor_old_target, self.terminal_continuation, self.semantic_target, *self.source_corridor, *self.cloned_corridor)
        _validate_route_ref_coherence(refs)
        if type(self.source_corridor) is not tuple or type(self.cloned_corridor) is not tuple or type(self.semantic_prefixes) is not tuple:
            raise TypeError("corridors and prefixes must be exact tuples")
        if not self.source_corridor or len(self.source_corridor) != len(self.cloned_corridor) or len(self.semantic_prefixes) != len(self.source_corridor):
            raise ValueError("corridor source/clone/prefix lengths must match and be positive")
        if self.proof_source != self.source_corridor[0]:
            raise ValueError("corridor proof source must be the first source member")
        if len(set(self.source_corridor)) != len(self.source_corridor):
            raise ValueError("corridor source members must be unique and ordered")
        if len(set(self.cloned_corridor)) != len(self.cloned_corridor):
            raise ValueError("corridor clone members must be unique and ordered")
        if set(self.source_corridor) & set(self.cloned_corridor):
            raise ValueError("corridor source and clone members must be disjoint")
        expected_old_target = (
            self.source_corridor[1]
            if len(self.source_corridor) > 1 else self.terminal_continuation
        )
        if self.descriptor_old_target != expected_old_target:
            raise ValueError("corridor descriptor old target is incoherent")
        if self.predecessor == self.source_corridor[0]:
            raise ValueError("corridor predecessor must precede the source corridor")
        if self.semantic_target in set(self.source_corridor) | set(self.cloned_corridor):
            raise ValueError("corridor semantic target must be outside source and clone members")
        if any(type(item) is not ClonedSemanticPrefix for item in self.semantic_prefixes):
            raise TypeError("semantic_prefixes must contain exact prefixes")
        owners = tuple(item.clone_owner.ref for item in self.semantic_prefixes)
        _validate_creation_spec_rows(self.creation_spec_digests, owners)
        for index, prefix in enumerate(self.semantic_prefixes):
            if prefix.ordinal != index or prefix.source_owner != self.source_corridor[index] or prefix.clone_owner != self.cloned_corridor[index]:
                raise ValueError("corridor prefixes do not follow exact corridor order")
            if prefix.creation_spec_row != self.creation_spec_digests[index]:
                raise ValueError("corridor prefix creation row differs from relation rows")
            expected_successor = (
                self.cloned_corridor[index + 1]
                if index + 1 < len(self.cloned_corridor) else self.semantic_target
            )
            if prefix.projected_successor != expected_successor:
                raise ValueError("corridor prefix projected successor is incoherent")
        _id(self.relation_id, "relation_id")
        expected = route_realization_id((
            "cloned_route_corridor", self.predecessor, self.proof_source,
            self.descriptor_old_target, self.terminal_continuation,
            self.source_corridor, self.cloned_corridor, self.semantic_target,
            self.semantic_prefixes, self.creation_spec_digests,
        ))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match route corridor")

    __copy__ = _reject_route_copy; __deepcopy__ = _reject_route_copy; __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ClonedCarrierRouteCorridorRealization:
    """Exact carrier relation with distinct semantic and physical sources."""

    proof_source: AnchoredBlockRef
    physical_feeder: AnchoredBlockRef
    comparison_entry: AnchoredBlockRef
    source_corridor: tuple[AnchoredBlockRef, ...]
    cloned_corridor: tuple[AnchoredBlockRef, ...]
    semantic_target: AnchoredBlockRef
    semantic_prefixes: tuple[ClonedSemanticPrefix, ...]
    creation_spec_digests: tuple[tuple[PlanBlockRef, str], ...]
    relation_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("carrier corridor realizations are binder-owned")

    def __post_init__(self) -> None:
        refs = (
            self.proof_source, self.physical_feeder, self.comparison_entry,
            self.semantic_target, *self.source_corridor,
            *self.cloned_corridor,
        )
        _validate_route_ref_coherence(refs)
        if (
            type(self.source_corridor) is not tuple
            or type(self.cloned_corridor) is not tuple
            or type(self.semantic_prefixes) is not tuple
        ):
            raise TypeError("carrier corridors and prefixes must be exact tuples")
        if (
            self.source_corridor != (self.physical_feeder,)
            or len(self.cloned_corridor) != 1
            or len(self.semantic_prefixes) != 1
        ):
            raise ValueError("exact carrier relation requires one feeder clone")
        if self.proof_source == self.physical_feeder:
            raise ValueError("carrier proof source and physical feeder must differ")
        primary_roles = (
            self.proof_source, self.physical_feeder,
            self.comparison_entry, self.semantic_target,
            *self.cloned_corridor,
        )
        if len(set(primary_roles)) != len(primary_roles):
            raise ValueError("carrier relation roles are incoherent")
        if set(self.source_corridor) & set(self.cloned_corridor):
            raise ValueError("carrier source and clone corridors must be disjoint")
        prefix = self.semantic_prefixes[0]
        if type(prefix) is not ClonedSemanticPrefix:
            raise TypeError("carrier semantic prefix must be exact")
        _validate_creation_spec_rows(
            self.creation_spec_digests, (self.cloned_corridor[0].ref,),
        )
        if (
            prefix.ordinal != 0
            or prefix.source_owner != self.physical_feeder
            or prefix.clone_owner != self.cloned_corridor[0]
            or prefix.projected_successor != self.semantic_target
            or prefix.creation_spec_row != self.creation_spec_digests[0]
        ):
            raise ValueError("carrier prefix does not follow the exact feeder clone")
        _id(self.relation_id, "relation_id")
        expected = route_realization_id((
            "cloned_carrier_route_corridor", self.proof_source,
            self.physical_feeder, self.comparison_entry,
            self.source_corridor, self.cloned_corridor, self.semantic_target,
            self.semantic_prefixes, self.creation_spec_digests,
        ))
        if self.relation_id != expected:
            raise ValueError("relation_id does not match carrier corridor")

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ProjectedRouteRealizationRow:
    claim_id: str
    proof_id: str
    route_subject_id: str
    relation: DirectRouteRealization | SharedCarrierSourceBypassRouteRealization | RetainedPrefixRouteRealization | LoweredConditionalRouteRealization | ClonedConditionalRouteRealization | FoldedConditionalRouteRealization | TwoArmDirectBranchRouteRealization | BranchFallthroughHelperRouteRealization | ClonedRouteCorridorRealization | ClonedCarrierRouteCorridorRealization
    site_preservation: ProjectedRouteSitePreservation
    plan_step_index: int
    plan_step_type: PatchStepKind
    plan_step_digest: str
    source_fingerprint: str
    projected_fingerprint: str
    source_generation: int
    projected_generation: int
    row_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("projected route rows are transaction-owned")

    def __post_init__(self) -> None:
        _id(self.claim_id, "claim_id"); _id(self.proof_id, "proof_id"); _id(self.route_subject_id, "route_subject_id")
        if type(self.relation) not in {DirectRouteRealization, SharedCarrierSourceBypassRouteRealization, RetainedPrefixRouteRealization, LoweredConditionalRouteRealization, ClonedConditionalRouteRealization, FoldedConditionalRouteRealization, TwoArmDirectBranchRouteRealization, BranchFallthroughHelperRouteRealization, ClonedRouteCorridorRealization, ClonedCarrierRouteCorridorRealization}:
            raise TypeError("relation must be a closed route realization")
        self.relation.__post_init__()
        if type(self.site_preservation) is not ProjectedRouteSitePreservation:
            raise TypeError("site_preservation must be ProjectedRouteSitePreservation")
        self.site_preservation.__post_init__()
        _nonnegative(self.plan_step_index, "plan_step_index"); _enum(self.plan_step_type, PatchStepKind, "plan_step_type"); _id(self.plan_step_digest, "plan_step_digest")
        _id(self.source_fingerprint, "source_fingerprint"); _id(self.projected_fingerprint, "projected_fingerprint")
        _generation(self.source_generation); _generation(self.projected_generation)
        expected = projected_route_realization_row_id((self.claim_id, self.proof_id, self.route_subject_id,
            self.relation, self.plan_step_index, self.plan_step_type, self.plan_step_digest,
            self.source_fingerprint, self.projected_fingerprint,
            self.source_generation, self.projected_generation, self.site_preservation))
        if self.row_id != expected: raise ValueError("row_id does not match canonical content")
    __copy__ = _reject_route_copy; __deepcopy__ = _reject_route_copy; __reduce__ = _reject_route_copy

    @property
    def source_ref(self) -> CfgBlockRef:
        if type(self.relation) is SharedCarrierSourceBypassRouteRealization:
            return self.relation.proof_source.ref
        if type(self.relation) is RetainedPrefixRouteRealization:
            return self.relation.delivery_owner.ref
        if type(self.relation) in {DirectRouteRealization, LoweredConditionalRouteRealization, ClonedConditionalRouteRealization, FoldedConditionalRouteRealization, TwoArmDirectBranchRouteRealization, BranchFallthroughHelperRouteRealization}:
            return self.relation.feeder.ref
        if type(self.relation) is ClonedRouteCorridorRealization:
            return self.relation.predecessor.ref
        if type(self.relation) is ClonedCarrierRouteCorridorRealization:
            return self.relation.proof_source.ref
        raise TypeError("unknown route relation")

    @property
    def old_target_ref(self) -> CfgBlockRef:
        if type(self.relation) is SharedCarrierSourceBypassRouteRealization:
            return self.relation.shared_feeder.ref
        if type(self.relation) is RetainedPrefixRouteRealization:
            return self.relation.old_target.ref
        if type(self.relation) is DirectRouteRealization:
            return self.relation.old_target.ref
        if type(self.relation) is LoweredConditionalRouteRealization:
            return self.relation.old_target.ref
        if type(self.relation) is ClonedConditionalRouteRealization:
            return self.relation.old_target.ref
        if type(self.relation) is FoldedConditionalRouteRealization:
            return self.relation.discarded_target.ref
        if type(self.relation) is TwoArmDirectBranchRouteRealization:
            return self.relation.source_rewritten_arm.ref
        if type(self.relation) is BranchFallthroughHelperRouteRealization:
            return self.relation.source_fallthrough.ref
        if type(self.relation) is ClonedRouteCorridorRealization:
            return self.relation.proof_source.ref
        if type(self.relation) is ClonedCarrierRouteCorridorRealization:
            return self.relation.comparison_entry.ref
        raise TypeError("unknown route relation")

    @property
    def new_target_ref(self) -> CfgBlockRef | None:
        if type(self.relation) is SharedCarrierSourceBypassRouteRealization:
            return self.relation.semantic_target.ref
        if type(self.relation) is RetainedPrefixRouteRealization:
            return self.relation.new_target.ref
        if type(self.relation) is DirectRouteRealization:
            return self.relation.new_target.ref
        if type(self.relation) is TwoArmDirectBranchRouteRealization:
            return self.relation.projected_replacement_arm.ref
        if type(self.relation) is FoldedConditionalRouteRealization:
            return self.relation.selected_target.ref
        if type(self.relation) in {BranchFallthroughHelperRouteRealization, ClonedRouteCorridorRealization, ClonedCarrierRouteCorridorRealization}:
            return self.relation.semantic_target.ref
        if type(self.relation) in {LoweredConditionalRouteRealization, ClonedConditionalRouteRealization}:
            return None
        raise TypeError("unknown route relation")

    @property
    def realization_kind(self) -> RouteRealizationKind:
        if type(self.relation) in {DirectRouteRealization, SharedCarrierSourceBypassRouteRealization, RetainedPrefixRouteRealization}:
            return RouteRealizationKind.DIRECT_REDIRECT
        if type(self.relation) in {
            LoweredConditionalRouteRealization, ClonedConditionalRouteRealization,
            TwoArmDirectBranchRouteRealization, BranchFallthroughHelperRouteRealization,
        }:
            return RouteRealizationKind.CONDITIONAL_REDIRECT
        if type(self.relation) is FoldedConditionalRouteRealization:
            return RouteRealizationKind.FOLDED
        if type(self.relation) in {ClonedRouteCorridorRealization, ClonedCarrierRouteCorridorRealization}:
            return RouteRealizationKind.HELPER_CORRIDOR
        raise TypeError("unknown route relation")

    @property
    def conditional_roles(self) -> tuple[ConditionalRoleCoordinate, ...]:
        if type(self.relation) in {LoweredConditionalRouteRealization, ClonedConditionalRouteRealization}:
            return tuple(ConditionalRoleCoordinate(arm.role, arm.target.anchor_ea) for arm in self.relation.arms)
        if type(self.relation) is TwoArmDirectBranchRouteRealization:
            return (ConditionalRoleCoordinate(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, self.relation.untouched_arm.anchor_ea), ConditionalRoleCoordinate(SemanticEdgeRole.CONDITIONAL_TAKEN, self.relation.projected_replacement_arm.anchor_ea))
        if type(self.relation) is BranchFallthroughHelperRouteRealization:
            return (ConditionalRoleCoordinate(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, self.relation.helper.anchor_ea), ConditionalRoleCoordinate(SemanticEdgeRole.CONDITIONAL_TAKEN, self.relation.untouched_conditional_arm.anchor_ea))
        if type(self.relation) in {DirectRouteRealization, SharedCarrierSourceBypassRouteRealization, RetainedPrefixRouteRealization, FoldedConditionalRouteRealization, ClonedRouteCorridorRealization, ClonedCarrierRouteCorridorRealization}:
            return ()
        raise TypeError("unknown route relation")

    @property
    def helper_refs(self) -> tuple[CfgBlockRef, ...]:
        if type(self.relation) is ClonedConditionalRouteRealization:
            return (self.relation.replacement_clone.ref, self.relation.fallthrough_helper.ref)
        if type(self.relation) is BranchFallthroughHelperRouteRealization:
            return (self.relation.helper.ref,)
        if type(self.relation) is ClonedRouteCorridorRealization:
            return tuple(item.ref for item in self.relation.cloned_corridor)
        if type(self.relation) is ClonedCarrierRouteCorridorRealization:
            return tuple(item.ref for item in self.relation.cloned_corridor)
        if type(self.relation) in {
            DirectRouteRealization, SharedCarrierSourceBypassRouteRealization, RetainedPrefixRouteRealization,
            LoweredConditionalRouteRealization, FoldedConditionalRouteRealization,
            TwoArmDirectBranchRouteRealization,
        }:
            return ()
        raise TypeError("unknown route relation")

    @property
    def creation_spec_digests(self) -> tuple[tuple[PlanBlockRef, str], ...]:
        if type(self.relation) is ClonedConditionalRouteRealization:
            return self.relation.creation_spec_digests
        if type(self.relation) in {BranchFallthroughHelperRouteRealization, ClonedRouteCorridorRealization, ClonedCarrierRouteCorridorRealization}:
            return self.relation.creation_spec_digests
        if type(self.relation) in {
            DirectRouteRealization, SharedCarrierSourceBypassRouteRealization, RetainedPrefixRouteRealization,
            LoweredConditionalRouteRealization, FoldedConditionalRouteRealization,
            TwoArmDirectBranchRouteRealization,
        }:
            return ()
        raise TypeError("unknown route relation")


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ProjectedRouteRealization:
    source_authority: SourceBoundRouteAuthority
    attempt_id: TransactionAttemptId
    plan_id: str
    rows: tuple[ProjectedRouteRealizationRow, ...]
    site_phase_result: ProjectedSemanticSitePhaseResult
    projected_inventory_digest: str
    projected_fingerprint: str
    projected_generation: int
    realization_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("projected route realization is transaction-owned")

    def __post_init__(self) -> None:
        if type(self.source_authority) is not SourceBoundRouteAuthority:
            raise TypeError("source_authority must be SourceBoundRouteAuthority")
        if type(self.attempt_id) is not TransactionAttemptId:
            raise TypeError("attempt_id must be TransactionAttemptId")
        if self.attempt_id.plan_id != self.source_authority.plan_id or self.plan_id != self.source_authority.plan_id:
            raise ValueError("projected realization plan differs from source authority")
        if self.projected_generation != self.attempt_id.generation:
            raise ValueError("projected realization generation differs from attempt")
        if type(self.site_phase_result) is not ProjectedSemanticSitePhaseResult:
            raise TypeError("site_phase_result must be ProjectedSemanticSitePhaseResult")
        self.site_phase_result.__post_init__()
        rows = tuple(self.rows)
        if any(type(row) is not ProjectedRouteRealizationRow for row in rows):
            raise TypeError("rows must contain ProjectedRouteRealizationRow values")
        for row in rows:
            row.__post_init__()
            if row.site_preservation.site_phase_result_id != self.site_phase_result.result_id:
                raise ValueError("route row preservation references a foreign site phase result")
        if len({row.row_id for row in rows}) != len(rows) or rows != tuple(sorted(rows, key=lambda row: row.row_id)):
            raise ValueError("projected realization rows must be sorted and unique")
        if any(row.plan_step_index < 0 for row in rows):
            raise ValueError("projected realization row step index must be non-negative")
        claims = {
            claim.claim_id: claim
            for claim in self.source_authority.proposal.claims
            if type(claim) is EquivalentSemanticRouteClaim
        }
        expected_pairs = {
            (claim_id, claim.route_proof_ids[0], claim.retired_route_subject.subject_id)
            for claim_id, claim in claims.items()
        }
        if len(rows) != len(expected_pairs):
            raise ValueError("projected realization row count must equal route claim count")
        actual_pairs = {(row.claim_id, row.proof_id, row.route_subject_id) for row in rows}
        if len(actual_pairs) != len(rows):
            raise ValueError("projected realization rows must have unique claim coordinates")
        if actual_pairs != expected_pairs:
            raise ValueError("projected realization must cover every route claim exactly once")
        for row in rows:
            if row.source_fingerprint != self.source_authority.source_fingerprint or row.source_generation != self.source_authority.source_generation:
                raise ValueError("projected row source coordinates differ from source authority")
            if row.projected_fingerprint != self.projected_fingerprint or row.projected_generation != self.projected_generation:
                raise ValueError("projected row coordinates differ from realization")
            if type(row.relation) is DirectRouteRealization:
                relation_refs = (
                    row.relation.feeder, row.relation.old_target, row.relation.new_target,
                )
            elif type(row.relation) is SharedCarrierSourceBypassRouteRealization:
                relation_refs = (
                    row.relation.proof_source,
                    row.relation.shared_feeder,
                    row.relation.comparison_entry,
                    row.relation.semantic_target,
                )
            elif type(row.relation) is RetainedPrefixRouteRealization:
                relation_refs = (
                    row.relation.proof_source,
                    row.relation.delivery_owner,
                    row.relation.old_target,
                    row.relation.new_target,
                )
            elif type(row.relation) is LoweredConditionalRouteRealization:
                relation_refs = (
                    row.relation.feeder, row.relation.proof_source, row.relation.old_target,
                    *(arm.target for arm in row.relation.arms),
                )
            elif type(row.relation) is ClonedConditionalRouteRealization:
                relation_refs = (
                    row.relation.feeder, row.relation.proof_source, row.relation.old_target,
                    row.relation.replacement_clone, row.relation.fallthrough_helper,
                    *(arm.target for arm in row.relation.arms),
                )
            elif type(row.relation) is FoldedConditionalRouteRealization:
                relation_refs = (
                    row.relation.feeder,
                    row.relation.selected_target,
                    row.relation.discarded_target,
                )
            elif type(row.relation) is TwoArmDirectBranchRouteRealization:
                relation_refs = (row.relation.feeder, row.relation.source_rewritten_arm, row.relation.projected_replacement_arm, row.relation.untouched_arm)
            elif type(row.relation) is BranchFallthroughHelperRouteRealization:
                relation_refs = (row.relation.feeder, row.relation.source_fallthrough, row.relation.untouched_conditional_arm, row.relation.helper, row.relation.semantic_target)
            elif type(row.relation) is ClonedRouteCorridorRealization:
                relation_refs = (row.relation.predecessor, row.relation.proof_source, row.relation.descriptor_old_target, row.relation.terminal_continuation, row.relation.semantic_target, *row.relation.source_corridor, *row.relation.cloned_corridor, *(item.source_owner for item in row.relation.semantic_prefixes), *(item.clone_owner for item in row.relation.semantic_prefixes), *(item.projected_successor for item in row.relation.semantic_prefixes))
            elif type(row.relation) is ClonedCarrierRouteCorridorRealization:
                relation_refs = (
                    row.relation.proof_source,
                    row.relation.physical_feeder,
                    row.relation.comparison_entry,
                    row.relation.semantic_target,
                    *row.relation.source_corridor,
                    *row.relation.cloned_corridor,
                    *(item.source_owner for item in row.relation.semantic_prefixes),
                    *(item.clone_owner for item in row.relation.semantic_prefixes),
                    *(item.projected_successor for item in row.relation.semantic_prefixes),
                )
            else:
                raise TypeError("unknown projected route relation")
            for anchored in relation_refs:
                ref = anchored.ref
                if type(ref) is NativeBlockRef and ref.identity.native_key != self.source_authority.source_native_key:
                    raise ValueError("projected row native reference uses a foreign native key")
                if type(ref) is LogicalBlockRef and ref.session_id != self.attempt_id.session_id:
                    raise ValueError("projected row logical reference uses a foreign session")
                if type(ref) is PlanBlockRef and ref.plan_id != self.plan_id:
                    raise ValueError("projected row plan reference uses a foreign plan")
        _id(self.projected_inventory_digest, "projected_inventory_digest"); _id(self.projected_fingerprint, "projected_fingerprint"); _generation(self.projected_generation)
        expected = projected_route_realization_id((self.source_authority.source_authority_id,
            self.attempt_id, self.plan_id, rows, self.projected_inventory_digest,
            self.projected_fingerprint, self.projected_generation, self.site_phase_result))
        if self.realization_id != expected: raise ValueError("realization_id does not match canonical content")
    __copy__ = _reject_route_copy; __deepcopy__ = _reject_route_copy; __reduce__ = _reject_route_copy


def _reject_binder_record_copy(self, *args, **kwargs):
    raise TypeError("binder-owned records cannot be copied")


def _reject_binder_record_pickle(self, *args, **kwargs):
    raise TypeError("binder-owned records cannot be pickled")


for _binder_record_type in (
    RawEffectGatePhaseFact,
    EffectSiteCoordinate,
    TerminalSiteCoordinate,
    ScalarizedInstructionCoordinate,
    ExactEffectBindingResult,
    LocalAliasScalarizationBindingResult,
    ProjectedEffectSiteResult,
    ProjectedTerminalSiteResult,
    ProjectedSemanticSitePhaseResult,
    ProjectedRouteSitePreservation,
    ProjectedRouteRealizationRow,
    ProjectedRouteRealization,
):
    _binder_record_type.__copy__ = _reject_binder_record_copy
    _binder_record_type.__deepcopy__ = _reject_binder_record_copy
    _binder_record_type.__reduce_ex__ = _reject_binder_record_pickle


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class SourceBoundRouteAuthorityAccepted:
    authority: SourceBoundRouteAuthority

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("route authority results are binder-owned")

    def __post_init__(self) -> None:
        if type(self.authority) is not SourceBoundRouteAuthority: raise TypeError("authority must be SourceBoundRouteAuthority")
        self.authority.__post_init__()

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class SourceBoundRouteAuthorityRejected:
    failures: tuple[RouteRealizationFailure, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("route authority results are binder-owned")

    def __post_init__(self) -> None:
        failures = self.failures
        if type(failures) is not tuple or not failures or any(type(item) is not RouteRealizationFailure for item in failures): raise ValueError("rejected source authority requires typed failures")
        for failure in failures:
            failure.__post_init__()
        if len(set(failures)) != len(failures) or failures != tuple(sorted(failures, key=lambda item: (item.claim_id or "", item.proof_id or "", item.stage.value))): raise ValueError("source failures must be sorted and unique")
        object.__setattr__(self, "failures", failures)

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ProjectedRouteRealizationAccepted:
    realization: ProjectedRouteRealization
    def __init__(self, *args: object, **kwargs: object) -> None: del args, kwargs; raise TypeError("route realization results are binder-owned")

    def __post_init__(self) -> None:
        if type(self.realization) is not ProjectedRouteRealization: raise TypeError("realization must be ProjectedRouteRealization")
        self.realization.__post_init__()

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ProjectedRouteRealizationRejected:
    failures: tuple[RouteRealizationFailure, ...]
    def __init__(self, *args: object, **kwargs: object) -> None: del args, kwargs; raise TypeError("route realization results are binder-owned")

    def __post_init__(self) -> None:
        failures = self.failures
        if type(failures) is not tuple or not failures or any(type(item) is not RouteRealizationFailure for item in failures): raise ValueError("rejected projected realization requires typed failures")
        for failure in failures:
            failure.__post_init__()
        if len(set(failures)) != len(failures) or failures != tuple(sorted(failures, key=lambda item: (item.claim_id or "", item.proof_id or "", item.stage.value))): raise ValueError("projected failures must be sorted and unique")
        object.__setattr__(self, "failures", failures)

    __copy__ = _reject_route_copy
    __deepcopy__ = _reject_route_copy
    __reduce__ = _reject_route_copy


SourceBoundRouteAuthorityResult: TypeAlias = SourceBoundRouteAuthorityAccepted | SourceBoundRouteAuthorityRejected
# Public kernel spelling used by the transaction boundary.  Keep the model
# name explicit as well: both aliases denote the same closed sum.
SourceRouteAuthorityResult: TypeAlias = SourceBoundRouteAuthorityResult
ProjectedRouteRealizationResult: TypeAlias = ProjectedRouteRealizationAccepted | ProjectedRouteRealizationRejected
__all__ = [
    name for name, value in tuple(globals().items())
    if (isinstance(value, type) and (getattr(value, "__module__", None) == __name__))
    or name in {"SemanticSubjectLocator", "AuthorityEvidencePayload", "ProducerUnflattenClaim", "TransactionDerivedUnflattenClaim", "UnflattenClaim", "CorridorCoverageForecastAuthority", "CorridorCoveragePhaseResultAuthority", "corridor_base_forecast", "corridor_base_phase_result", "CLONED_SEMANTIC_OBSERVATION_SCHEMA", "CLONED_SEMANTIC_ORIGIN_SCHEMA", "CLONED_SEMANTIC_PREFIX_SCHEMA", "cloned_semantic_observation_digest", "cloned_semantic_instruction_origin_id", "cloned_semantic_prefix_id"}
]
