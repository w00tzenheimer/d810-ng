"""Closed, portable semantic-authority records for unflatten planning.

This module deliberately contains no evaluator, graph traversal, hashing, or
live SDK object.  It is the immutable vocabulary shared by the producer and
the later transaction authority implementation.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import re
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.typing import Literal, TypeAlias
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity
from d810.transforms.cfg_transaction import (
    CfgBlockRef,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
)
from .ids import _subject_id_from_record, _validate_id, claim_id, evidence_id


_BADADDR = 0xFFFFFFFFFFFFFFFF
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
class TopologyEvidencePayload:
    subject_id: str
    predecessor_subject_ids: tuple[str, ...]
    successor_subject_ids: tuple[str, ...]
    reciprocal_edges: bool
    expected_shape_digest: str
    candidate_shape_digest: str

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


@dataclass(frozen=True, slots=True)
class StructuralLineageEvidencePayload:
    source_subject_id: str
    candidate_subject_ids: tuple[str, ...]
    disposition: StructuralDisposition
    reciprocal_native_origin_eas: tuple[int, ...]
    claim_id: str | None

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
            object.__setattr__(self, name, values)
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
        object.__setattr__(self, "violation_ids", violations)


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
        if self.schema_version != 1 or self.rule_set_version != 1:
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
        if not self.use_def_witness.executed or not self.use_def_witness.fragment_atomic or self.use_def_witness.actionable_non_state_severance_count:
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


__all__ = [
    name for name, value in tuple(globals().items())
    if (isinstance(value, type) and (getattr(value, "__module__", None) == __name__))
    or name in {"SemanticSubjectLocator", "AuthorityEvidencePayload", "ProducerUnflattenClaim", "TransactionDerivedUnflattenClaim", "UnflattenClaim"}
]
