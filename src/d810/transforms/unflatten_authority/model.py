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
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.typing import Literal, Protocol, TypeAlias, runtime_checkable
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.maturity import MaturityEnvelope
from d810.ir.storage_identity import StorageIdentity
from d810.transforms.cfg_transaction import (
    CfgBlockRef,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
    TransactionAttemptId,
)
from .ids import (
    _subject_id_from_record,
    _validate_id,
    authority_id,
    case_id,
    claim_id,
    evidence_id,
    justification_id,
    receipt_id,
)
from .legacy_keys import LEGACY_UNFLATTEN_KEYS
from .legacy_wire import decode_legacy_value


_BADADDR = 0xFFFFFFFFFFFFFFFF
_OBLIGATION_INDEX_TOKEN = object()
_PREPARATION_RECEIPT_TOKEN = object()
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
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
    if len(set(left)) != len(left) or len(set(right)) != len(right):
        raise ValueError(f"{left_label} and {right_label} must not contain duplicates")
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
        EquivalentSemanticRouteClaim,
        ExactInfeasibleEffectClaim,
        LocalAliasEffectScalarizationClaim,
        TerminalCycleBreakClaim,
    ):
        return ("claim", value.claim_id)
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


def _authority_ref(value: object, label: str = "block_ref") -> NativeBlockRef | LogicalBlockRef:
    if type(value) not in _AUTHORITY_REF_TYPES:
        raise TypeError(f"{label} must be a NativeBlockRef or LogicalBlockRef")
    return value


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
    SOURCE_ENTRY = "source_entry"
    DISPATCHER_ENTRY = "dispatcher_entry"
    DISPATCHER_INFRASTRUCTURE = "dispatcher_infrastructure"
    SEMANTIC_ROUTE_SOURCE = "semantic_route_source"
    SEMANTIC_ROUTE_DESTINATION = "semantic_route_destination"
    EFFECT_SITE = "effect_site"
    AUTHORITATIVE_HANDLER = "authoritative_handler"
    TERMINAL_SITE = "terminal_site"
    NON_STATE_VALUE_FLOW = "non_state_value_flow"
    DISPATCHER_CORRIDOR = "dispatcher_corridor"
    PLANNED_HELPER = "planned_helper"


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
    PATCH_STEP = "patch_step"
    GENERIC_CFG_GATE = "generic_cfg_gate"


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


class UnflattenPlanRoute(str, Enum):
    ORDINARY = "ordinary"
    TYPED_PROPOSAL = "typed_proposal"
    LEGACY_ADAPTED = "legacy_adapted"


class UnflattenPlanShape(str, Enum):
    EXACT_EFFECT_ONLY = "exact_effect_only"
    PARTIAL_REWRITE = "partial_rewrite"
    FULL_DISPATCHER_RETIREMENT = "full_dispatcher_retirement"


@dataclass(frozen=True, slots=True)
class BlockSubjectLocator:
    block_ref: CfgBlockRef
    anchor_ea: int

    def __post_init__(self) -> None:
        _cfg_ref(self.block_ref)
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))


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
    destination_refs: tuple[CfgBlockRef, ...]
    destination_anchor_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        _id(self.proof_id, "proof_id")
        _id(self.atomic_group_id, "atomic_group_id")
        _cfg_ref(self.source_ref, "source_ref")
        object.__setattr__(self, "source_anchor_ea", _ea(self.source_anchor_ea, "source_anchor_ea"))
        pairs = _paired_tuples(
            self.destination_refs, self.destination_anchor_eas,
            "destination_refs", "destination_anchor_eas",
        )
        for ref, ea in pairs:
            _cfg_ref(ref, "destination_refs item")
            _ea(ea, "destination_anchor_eas item")
        object.__setattr__(self, "destination_refs", tuple(pair[0] for pair in pairs))
        object.__setattr__(self, "destination_anchor_eas", tuple(pair[1] for pair in pairs))


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
    block_ref: CfgBlockRef
    anchor_ea: int
    normalized_states: tuple[int, ...]

    def __post_init__(self) -> None:
        _cfg_ref(self.block_ref)
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))
        states = _tuple(self.normalized_states, "normalized_states", sort=True)
        for state in states:
            _nonnegative(state, "normalized state")
        if not states:
            raise ValueError("normalized_states must not be empty")
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
        refs = _tuple(self.redirect_owner_refs, "redirect_owner_refs", sort=True)
        for ref in refs:
            _cfg_ref(ref)
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
        pairs = _paired_tuples(
            self.member_refs, self.member_anchor_eas,
            "member_refs", "member_anchor_eas",
        )
        for ref, ea in pairs:
            _cfg_ref(ref, "member_refs item")
            _ea(ea, "member_anchor_eas item")
        refs = tuple(pair[0] for pair in pairs)
        eas = tuple(pair[1] for pair in pairs)
        if self.entry_ref not in refs:
            raise ValueError("corridor members must include entry_ref")
        object.__setattr__(self, "member_refs", refs)
        object.__setattr__(self, "member_anchor_eas", eas)


SemanticSubjectLocator: TypeAlias = (
    BlockSubjectLocator | EdgeSubjectLocator | RouteSubjectLocator
    | EffectSubjectLocator | HandlerSubjectLocator | TerminalSubjectLocator
    | ValueFlowSubjectLocator | CorridorSubjectLocator
)


_SUBJECT_MATRIX = {
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SOURCE_ENTRY): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_ENTRY): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.EFFECT_SITE): BlockSubjectLocator,
    (SemanticSubjectKind.BLOCK, SemanticSubjectRole.PLANNED_HELPER): BlockSubjectLocator,
    (SemanticSubjectKind.EDGE, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): EdgeSubjectLocator,
    (SemanticSubjectKind.ROUTE, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE): RouteSubjectLocator,
    (SemanticSubjectKind.EFFECT, SemanticSubjectRole.EFFECT_SITE): EffectSubjectLocator,
    (SemanticSubjectKind.HANDLER, SemanticSubjectRole.AUTHORITATIVE_HANDLER): HandlerSubjectLocator,
    (SemanticSubjectKind.TERMINAL, SemanticSubjectRole.TERMINAL_SITE): TerminalSubjectLocator,
    (SemanticSubjectKind.VALUE_FLOW, SemanticSubjectRole.NON_STATE_VALUE_FLOW): ValueFlowSubjectLocator,
    (SemanticSubjectKind.CORRIDOR, SemanticSubjectRole.DISPATCHER_CORRIDOR): CorridorSubjectLocator,
}


def _subject_owner(locator: SemanticSubjectLocator) -> tuple[CfgBlockRef | None, int | None]:
    if isinstance(locator, BlockSubjectLocator):
        return locator.block_ref, locator.anchor_ea
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
        if expected is None or type(self.locator) is not expected:
            raise ValueError("unsupported subject kind/role/locator")
        if type(self.block_ref) not in _CFG_REF_TYPES and self.block_ref is not None:
            raise TypeError("block_ref must be a CfgBlockRef or None")
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
        if self.status is SubjectBindingStatus.UNIQUE:
            if self.subject.block_ref is None or self.block_ref != self.subject.block_ref:
                raise ValueError("unique binding requires block_ref")
            if self.serial is None or self.anchor_ea is None or not eas:
                raise ValueError("unique binding requires serial, anchor, and native EAs")
        elif self.serial is not None or self.anchor_ea is not None:
            raise ValueError("non-unique binding requires no serial or anchor")


@dataclass(frozen=True, slots=True)
class PhaseBindingEvidencePayload:
    binding: PhaseSubjectBinding

    def __post_init__(self) -> None:
        if type(self.binding) is not PhaseSubjectBinding:
            raise TypeError("binding must be a PhaseSubjectBinding")


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

    def __post_init__(self) -> None:
        for name in ("route_subject_id", "atomic_group_id", "source_subject_id"):
            _id(getattr(self, name), name)
        for name in ("proof_ids", "destination_subject_ids"):
            values = _tuple(getattr(self, name), name, sort=True)
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
    member_subject_ids: tuple[str, ...]
    covered_subject_ids: tuple[str, ...]
    residual_subject_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.corridor_subject_id, "corridor_subject_id")
        for name in ("member_subject_ids", "covered_subject_ids", "residual_subject_ids"):
            values = _tuple(getattr(self, name), name, sort=True)
            for value in values:
                _id(value, f"{name} item")
            object.__setattr__(self, name, values)


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


def _claim_subject(value: object, kind: SemanticSubjectKind, role: SemanticSubjectRole, locator: type, label: str) -> None:
    if type(value) is not SemanticSubjectRef:
        raise TypeError(f"{label} must be a SemanticSubjectRef")
    if value.kind is not kind or value.role is not role or type(value.locator) is not locator:
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
        *tuple(zip(locator.destination_refs, locator.destination_anchor_eas)),
    )


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
    if type(locator) is EdgeSubjectLocator:
        return (locator.source_ref, locator.target_ref)
    if type(locator) is RouteSubjectLocator:
        return (locator.source_ref, *locator.destination_refs)
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
    if type(locator) is EdgeSubjectLocator:
        return (
            (locator.source_ref, locator.source_anchor_ea),
            (locator.target_ref, locator.target_anchor_ea),
        )
    if type(locator) is RouteSubjectLocator:
        return (
            (locator.source_ref, locator.source_anchor_ea),
            *tuple(zip(locator.destination_refs, locator.destination_anchor_eas)),
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
    retirement_proof_ids: tuple[str, ...]
    source_generation: int

    def __post_init__(self) -> None:
        _claim_common(self.claim_id, self.kind, UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE, self.source_generation)
        _claim_subject(self.infrastructure_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, BlockSubjectLocator, "infrastructure_subject")
        _claim_subject(self.corridor_subject, SemanticSubjectKind.CORRIDOR, SemanticSubjectRole.DISPATCHER_CORRIDOR, CorridorSubjectLocator, "corridor_subject")
        members = _tuple(self.member_subjects, "member_subjects", sort=True)
        for member in members:
            _claim_subject(member, SemanticSubjectKind.BLOCK, SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, BlockSubjectLocator, "member_subject")
        proofs = _tuple(self.retirement_proof_ids, "retirement_proof_ids", sort=True)
        for proof in proofs:
            _id(proof, "retirement_proof_ids item")
        object.__setattr__(self, "member_subjects", members)
        object.__setattr__(self, "retirement_proof_ids", proofs)
        expected_members = tuple(
            zip(self.corridor_subject.locator.member_refs,
                self.corridor_subject.locator.member_anchor_eas)
        )
        actual_members = tuple(_subject_block_pair(member) for member in members)
        if set(actual_members) != set(expected_members):
            raise ValueError("retirement members must match corridor members")
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

    def __post_init__(self) -> None:
        _claim_common(self.claim_id, self.kind, UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE, self.source_generation)
        for name in ("retired_route_subject", "replacement_route_subject"):
            _claim_subject(getattr(self, name), SemanticSubjectKind.ROUTE, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, RouteSubjectLocator, name)
        _claim_subject(self.source_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, BlockSubjectLocator, "source_subject")
        destinations = _tuple(self.destination_subjects, "destination_subjects", sort=True)
        for subject in destinations:
            _claim_subject(subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, BlockSubjectLocator, "destination_subject")
        proofs = _tuple(self.route_proof_ids, "route_proof_ids", sort=True)
        for proof in proofs:
            _id(proof, "route_proof_ids item")
        _id(self.atomic_group_id, "atomic_group_id")
        object.__setattr__(self, "destination_subjects", destinations)
        object.__setattr__(self, "route_proof_ids", proofs)
        source_pair = _subject_block_pair(self.source_subject)
        destination_pairs = tuple(_subject_block_pair(subject) for subject in destinations)
        retired_pairs = _route_pairs(self.retired_route_subject)
        replacement_pairs = _route_pairs(self.replacement_route_subject)
        if (
            retired_pairs[0] != source_pair
            or replacement_pairs[0] != source_pair
            or set(retired_pairs[1:]) != set(destination_pairs)
            or set(replacement_pairs[1:]) != set(destination_pairs)
        ):
            raise ValueError("route claim subjects must match route locator members")
        if (
            self.atomic_group_id != self.retired_route_subject.locator.atomic_group_id
            or self.atomic_group_id != self.replacement_route_subject.locator.atomic_group_id
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
        for name in ("source_subject", "predicate_subject"):
            _claim_subject(getattr(self, name), SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, BlockSubjectLocator, name)
        _claim_subject(self.selected_target_subject, SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, BlockSubjectLocator, "selected_target_subject")
        _nonnegative(self.normalized_state, "normalized_state")
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("state_identity must be a StorageIdentity")
        if self.width <= 0:
            raise ValueError("width must be positive")
        _nonnegative(self.width, "width")
        for name in ("source_write_ea", "predicate_branch_ea", "discarded_effect_ea"):
            object.__setattr__(self, name, _ea(getattr(self, name), name))
        _enum(self.selected_edge_role, SemanticEdgeRole, "selected_edge_role")
        proofs = _tuple(self.route_proof_ids, "route_proof_ids", sort=True)
        for proof in proofs:
            _id(proof, "route_proof_ids item")
        object.__setattr__(self, "route_proof_ids", proofs)
        if type(self.consensus) is not ProviderConsensusWitness:
            raise TypeError("consensus must be a ProviderConsensusWitness")
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
                raise ValueError("host_text_sha1 must be lowercase 40-hex or None")
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
        _claim_subject(self.terminal_subject, SemanticSubjectKind.TERMINAL, SemanticSubjectRole.TERMINAL_SITE, TerminalSubjectLocator, "terminal_subject")
        proofs = _tuple(self.terminal_route_proof_ids, "terminal_route_proof_ids", sort=True)
        for proof in proofs:
            _id(proof, "terminal_route_proof_ids item")
        object.__setattr__(self, "terminal_route_proof_ids", proofs)
        if self.claim_id != claim_id(self):
            raise ValueError("claim_id does not match canonical claim content")


ProducerUnflattenClaim: TypeAlias = (
    RetiredDispatcherInfrastructureClaim | EquivalentSemanticRouteClaim
    | ExactInfeasibleEffectClaim | TerminalCycleBreakClaim
)
TransactionDerivedUnflattenClaim: TypeAlias = LocalAliasEffectScalarizationClaim
UnflattenClaim: TypeAlias = ProducerUnflattenClaim | TransactionDerivedUnflattenClaim


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
        refs = _tuple(self.redirect_owner_refs, "redirect_owner_refs", sort=True)
        for ref in refs:
            _cfg_ref(ref)
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


@dataclass(frozen=True, slots=True)
class SourceBlockIdentityWitness:
    block_ref: NativeBlockRef | LogicalBlockRef
    anchor_ea: int
    native_instruction_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        _authority_ref(self.block_ref)
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))
        eas = _tuple(self.native_instruction_eas, "native_instruction_eas", sort=True)
        if not eas:
            raise ValueError("native_instruction_eas must not be empty")
        for ea in eas:
            _ea(ea, "native_instruction_eas item")
        if self.anchor_ea not in eas:
            raise ValueError("anchor_ea must belong to native_instruction_eas")
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
        anchors = tuple(block.anchor_ea for block in blocks)
        instruction_eas = tuple(
            ea for block in blocks for ea in block.native_instruction_eas
        )
        if (
            len(set(refs)) != len(refs)
            or len(set(anchors)) != len(anchors)
            or len(set(instruction_eas)) != len(instruction_eas)
        ):
            raise ValueError("source catalog block witnesses must be unique")
        object.__setattr__(self, "blocks", blocks)


@dataclass(frozen=True, slots=True)
class AuthoritativeHandlerInput:
    block_ref: NativeBlockRef | LogicalBlockRef
    anchor_ea: int
    normalized_states: tuple[int, ...]

    def __post_init__(self) -> None:
        _authority_ref(self.block_ref)
        object.__setattr__(self, "anchor_ea", _ea(self.anchor_ea, "anchor_ea"))
        states = _tuple(self.normalized_states, "normalized_states", sort=True)
        if not states:
            raise ValueError("normalized_states must not be empty")
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
        try:
            decode_legacy_value(self.canonical_payload)
        except Exception as exc:
            raise ValueError("canonical_payload must be canonical bytes") from exc
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
            if type(claim) not in (RetiredDispatcherInfrastructureClaim, EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim, TerminalCycleBreakClaim):
                raise TypeError("claims must contain producer claims only")
        if len({claim.claim_id for claim in claims}) != len(claims):
            raise ValueError("claims must not contain duplicate IDs")
        object.__setattr__(self, "claims", claims)
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
                    if witness is None:
                        raise ValueError("proposal subject reference is absent from source catalog")
                    if anchor is not None and witness.anchor_ea != anchor:
                        raise ValueError("proposal subject anchor disagrees with source catalog")
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
        retired_refs = {
            member.locator.block_ref
            for claim in claims
            if type(claim) is RetiredDispatcherInfrastructureClaim
            for member in claim.member_subjects
        }
        if not retired_refs <= dispatcher_member_refs:
            raise ValueError("retired refs must be a subset of dispatcher_member_refs")
        handler_refs = {
            handler.block_ref for handler in self.plan_inputs.authoritative_handlers
        }
        if handler_refs & retired_refs:
            raise ValueError("authoritative handlers must be disjoint from retired infrastructure")
        if self.plan_inputs.shape is UnflattenPlanShape.EXACT_EFFECT_ONLY:
            if (
                claim_kinds != {UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT}
                or retired_refs
            ):
                raise ValueError("exact-effect-only plan has incompatible claim families")
        elif self.plan_inputs.shape is UnflattenPlanShape.PARTIAL_REWRITE:
            if not claim_kinds.intersection({
                UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
                UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
            }):
                raise ValueError("partial rewrite requires route or retirement claims")
            if not dispatcher_member_refs - retired_refs:
                raise ValueError("partial rewrite requires retained dispatcher members")
        elif self.plan_inputs.shape is UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT:
            if UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE not in claim_kinds:
                raise ValueError("full dispatcher retirement requires a retirement claim")
            if retired_refs != dispatcher_member_refs:
                raise ValueError("full dispatcher retirement must retire all dispatcher members")

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
class PreparationBuildMetrics:
    source_inventory_builds: int
    candidate_inventory_builds: int
    inventory_ms: float

    def __post_init__(self) -> None:
        if self.source_inventory_builds != 1 or self.candidate_inventory_builds != 1:
            raise ValueError("preparation must build each inventory exactly once")
        if type(self.inventory_ms) not in (int, float) or isinstance(self.inventory_ms, bool):
            raise TypeError("inventory_ms must be a finite nonnegative number")
        if not math.isfinite(float(self.inventory_ms)) or self.inventory_ms < 0:
            raise ValueError("inventory_ms must be a finite nonnegative number")


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
    metrics: PreparationBuildMetrics
    _token: object = dataclass_field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if getattr(self, "_token", None) is not _PREPARATION_RECEIPT_TOKEN:
            raise TypeError("preparation receipts are evaluator-owned")
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
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        if type(self.metrics) is not PreparationBuildMetrics:
            raise TypeError("metrics must be PreparationBuildMetrics")
        if self.receipt_id != receipt_id(self):
            raise ValueError("receipt_id does not match canonical receipt content")


@dataclass(frozen=True, slots=True)
class SemanticPhaseMetrics:
    preparation_metrics: PreparationBuildMetrics
    source_inventory_builds: int
    candidate_inventory_builds: int
    index_folds: int
    view_graph_traversals: int

    def __post_init__(self) -> None:
        if type(self.preparation_metrics) is not PreparationBuildMetrics:
            raise TypeError("preparation_metrics must be PreparationBuildMetrics")
        if (
            self.source_inventory_builds,
            self.candidate_inventory_builds,
            self.index_folds,
            self.view_graph_traversals,
        ) != (1, 1, 1, 0):
            raise ValueError("evaluator metrics must be exactly (1, 1, 1, 0)")


@dataclass(frozen=True, slots=True)
class DerivedUnflattenPreparationInputs:
    proposal: ProposedUnflattenContract
    claims: tuple[UnflattenClaim, ...]
    preparation_receipt: PreparationAuthorityReceipt
    source_subjects: tuple[SemanticSubjectRef, ...]
    candidate_subjects: tuple[SemanticSubjectRef, ...]
    source_bindings: tuple[PhaseSubjectBinding, ...]
    candidate_bindings: tuple[PhaseSubjectBinding, ...]
    conditional_relations: tuple[ConditionalSubjectRelation, ...]
    lineage_evidence: tuple[AuthorityEvidence, ...]
    patch_step_evidence: tuple[AuthorityEvidence, ...]
    generic_gates: tuple[GenericCfgGateResult, ...]
    source_fingerprint: str
    candidate_fingerprint: str
    source_generation: int
    candidate_generation: int
    preparation_metrics: PreparationBuildMetrics

    def __post_init__(self) -> None:
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("proposal must be a ProposedUnflattenContract")
        if type(self.preparation_receipt) is not PreparationAuthorityReceipt:
            raise TypeError("preparation_receipt must be PreparationAuthorityReceipt")
        if type(self.claims) is not tuple:
            raise TypeError("claims must be an exact tuple")
        for claim in self.claims:
            if type(claim) not in (RetiredDispatcherInfrastructureClaim,
                                   EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim,
                                   LocalAliasEffectScalarizationClaim, TerminalCycleBreakClaim):
                raise TypeError("claims must contain closed UnflattenClaim values")
        for name in ("source_subjects", "candidate_subjects"):
            values = _tuple(getattr(self, name), name, sort=True)
            if any(type(value) is not SemanticSubjectRef for value in values):
                raise TypeError(f"{name} must contain SemanticSubjectRef values")
            if len({value.subject_id for value in values}) != len(values):
                raise ValueError(f"{name} must not contain duplicate subjects")
            object.__setattr__(self, name, values)
        for name in ("source_bindings", "candidate_bindings"):
            values = _tuple(getattr(self, name), name, sort=True)
            if any(type(value) is not PhaseSubjectBinding for value in values):
                raise TypeError(f"{name} must contain PhaseSubjectBinding values")
            if len({value.subject.subject_id for value in values}) != len(values):
                raise ValueError(f"{name} must not contain duplicate subjects")
            object.__setattr__(self, name, values)
        relations = _tuple(self.conditional_relations, "conditional_relations", sort=True)
        if any(type(value) is not ConditionalSubjectRelation for value in relations):
            raise TypeError("conditional_relations must contain ConditionalSubjectRelation values")
        object.__setattr__(self, "conditional_relations", relations)
        for name in ("lineage_evidence", "patch_step_evidence"):
            values = _tuple(getattr(self, name), name)
            if any(type(value) is not AuthorityEvidence for value in values):
                raise TypeError(f"{name} must contain AuthorityEvidence values")
            object.__setattr__(self, name, values)
        gates = _tuple(self.generic_gates, "generic_gates")
        if any(type(value) is not GenericCfgGateResult for value in gates):
            raise TypeError("generic_gates must contain GenericCfgGateResult values")
        if len(gates) != len(GenericCfgGateKind) or {value.gate for value in gates} != set(GenericCfgGateKind):
            raise ValueError("generic_gates must contain exactly one row per gate")
        object.__setattr__(self, "generic_gates", gates)
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _generation(self.source_generation, "source_generation")
        _generation(self.candidate_generation, "candidate_generation")
        if type(self.preparation_metrics) is not PreparationBuildMetrics:
            raise TypeError("preparation_metrics must be PreparationBuildMetrics")


@dataclass(frozen=True, slots=True)
class SemanticSafetyCase:
    case_id: str
    authority_id: str
    preparation_receipt_id: str
    phase: UnflattenAuthorityPhase
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

    def __post_init__(self) -> None:
        _id(self.case_id, "case_id")
        _id(self.authority_id, "authority_id")
        _id(self.preparation_receipt_id, "preparation_receipt_id")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        _generation(self.candidate_generation, "candidate_generation")
        for name in ("claims", "subjects", "bindings", "conditional_relations", "required_obligations", "evidence", "justifications"):
            object.__setattr__(self, name, _tuple(getattr(self, name), name))
        if any(type(claim) not in (RetiredDispatcherInfrastructureClaim, EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim, LocalAliasEffectScalarizationClaim, TerminalCycleBreakClaim) for claim in self.claims):
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
        if type(self.obligation_index) is not ObligationEvidenceIndex:
            raise TypeError("obligation_index must be an ObligationEvidenceIndex")
        if type(self.phase_metrics) is not SemanticPhaseMetrics:
            raise TypeError("phase_metrics must be SemanticPhaseMetrics")
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


@runtime_checkable
class BoundPatchPlanAuthority(Protocol):
    plan: PatchPlanAuthority
    attempt_id: TransactionAttemptId
    session_id: str
    generation: int
    maturity: int
    bindings: tuple[tuple[CfgBlockRef, int], ...]


@dataclass(frozen=True, slots=True)
class PreparedUnflattenAuthority:
    authority_id: str
    route: UnflattenPlanRoute
    owning_plan: PatchPlanAuthority
    proposal: ProposedUnflattenContract
    claims: tuple[UnflattenClaim, ...]
    bound_routes: BoundCanonicalSemanticEvidence
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

    def __post_init__(self) -> None:
        _id(self.authority_id, "authority_id")
        _enum(self.route, UnflattenPlanRoute, "route")
        if not isinstance(self.owning_plan, PatchPlanAuthority):
            raise TypeError("owning_plan must satisfy PatchPlanAuthority")
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("proposal must be ProposedUnflattenContract")
        if type(self.bound_routes) is not BoundCanonicalSemanticEvidence:
            raise TypeError("bound_routes must be BoundCanonicalSemanticEvidence")
        _id(self.snapshot_id, "snapshot_id")
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
        if self.owning_plan.plan_id != self.proposal.plan_id:
            raise ValueError("owning plan does not match proposal")
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
        def coordinate_key(item: tuple[object, int]) -> tuple[str, int]:
            return repr(item[0]), item[1]
        expected_coordinates = tuple(sorted(
            ((block.block_ref, block.anchor_ea)
             for block in self.proposal.source_identity_catalog.blocks),
            key=coordinate_key,
        ))
        if tuple(sorted(self.owning_plan.source_coordinates, key=coordinate_key)) != expected_coordinates:
            raise ValueError("owning plan source coordinates do not match the proposal catalog")
        if self.source_coordinate_digest != authority_id(expected_coordinates):
            raise ValueError("source coordinate digest does not match the proposal catalog")
        source_binding_coordinates = tuple(sorted(
            ((binding.block_ref, binding.anchor_ea)
             for binding in self.source_bindings
             if binding.status is SubjectBindingStatus.UNIQUE
             and binding.block_ref is not None and binding.anchor_ea is not None),
            key=coordinate_key,
        ))
        if frozenset(source_binding_coordinates) != frozenset(expected_coordinates):
            raise ValueError("source bindings do not cover the proposal catalog")
        source_subjects = tuple(
            subject for subject in self.projected_case.subjects
            if subject.role is not SemanticSubjectRole.PLANNED_HELPER
        )
        if {binding.subject.subject_id for binding in self.source_bindings} != {
            subject.subject_id for subject in source_subjects
        }:
            raise ValueError("source bindings must cover every projected source subject exactly")
        if any(
            binding.subject != subject
            for subject in source_subjects
            for binding in self.source_bindings
            if binding.subject.subject_id == subject.subject_id
        ):
            raise ValueError("source binding subject identity does not match the projected source subject")
        if self.bound_routes.evidence != self.proposal.route_evidence:
            raise ValueError("bound routes do not exactly cover proposal route evidence")
        if tuple(sorted(route.evidence.proof_id for route in self.bound_routes.routes)) != tuple(sorted(proof.proof_id for proof in self.proposal.route_evidence.route_proofs)):
            raise ValueError("bound routes do not cover every proposal route proof")
        proofs = {proof.proof_id: proof for proof in self.proposal.route_evidence.route_proofs}
        for route in self.bound_routes.routes:
            proof = proofs.get(route.evidence.proof_id)
            if proof is None or route.evidence != proof:
                raise ValueError("bound route proof does not match portable evidence")
            if route.source.anchor_ea != proof.source_anchor_ea or route.source.identity != proof.source_identity:
                raise ValueError("bound route source does not match portable proof anchor")
            expected_destinations = {
                (destination.role, destination.target_anchor_ea, destination.target_identity)
                for destination in proof.destinations
            }
            actual_destinations = {
                (destination.evidence.role, destination.block.anchor_ea, destination.block.identity)
                for destination in route.destinations
            }
            if actual_destinations != expected_destinations:
                raise ValueError("bound route destinations do not match portable proof anchors")
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

    def __post_init__(self) -> None:
        _id(self.binding_id, "binding_id")
        if type(self.prepared) is not PreparedUnflattenAuthority:
            raise TypeError("prepared must be PreparedUnflattenAuthority")
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
        values = _tuple(self.live_bindings, "live_bindings")
        for ref, serial in values:
            _cfg_ref(ref)
            _nonnegative(serial, "live binding serial")
        object.__setattr__(self, "live_bindings", values)


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
        ):
            raise ValueError("preparation verdict does not match prepared authority")


@dataclass(frozen=True, slots=True)
class UnflattenAuthorityPreparationRejected:
    verdict: UnflattenAuthorityVerdict

    def __post_init__(self) -> None:
        if type(self.verdict) is not UnflattenAuthorityVerdict or self.verdict.accepted:
            raise ValueError("preparation rejected requires a rejected verdict")


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


__all__ = [
    name for name, value in tuple(globals().items())
    if (isinstance(value, type) and (getattr(value, "__module__", None) == __name__))
    or name in {"SemanticSubjectLocator", "AuthorityEvidencePayload", "ProducerUnflattenClaim", "TransactionDerivedUnflattenClaim", "UnflattenClaim"}
]
