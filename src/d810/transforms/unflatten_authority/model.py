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
    CanonicalRouteAssessment,
    CanonicalRouteAssessmentPhase,
    validate_canonical_route_assessment,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import NativeEaInterval, NativeEaIntervalSet, StableBlockIdentity
from d810.core.typing import Literal, Protocol, TypeAlias, runtime_checkable
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantics import CallKind, ControlTransferKind
from d810.ir.maturity import MaturityEnvelope
from d810.ir.storage_identity import StorageIdentity
from d810.transforms.patch_binding import BoundPatchPlan, validate_bound_patch_plan
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
    bound_unflatten_binding_id,
    canonical_bytes,
    canonical_decode,
    validate_canonical_roundtrip,
    case_id,
    claim_id,
    evidence_id,
    justification_id,
    receipt_id,
    semantic_graph_inventory_digest,
)
from .legacy_keys import LEGACY_UNFLATTEN_KEYS
from .legacy_wire import decode_legacy_value, encode_legacy_value
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


class SemanticLossKind(str, Enum):
    """Closed classifications for source-indexed semantic loss rows."""

    RETIRED_DISPATCHER_INFRASTRUCTURE = "retired_dispatcher_infrastructure"
    EQUIVALENT_SEMANTIC_ROUTE = "equivalent_semantic_route"
    EXACT_INFEASIBLE_EFFECT = "exact_infeasible_effect"
    TERMINAL_CYCLE_BREAK = "terminal_cycle_break"
    LOCAL_ALIAS_SCALARIZATION = "local_alias_scalarization"
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


class RetirementProofFamily(str, Enum):
    RETIRED_INFRASTRUCTURE = "retired_infrastructure"
    RETIRED_STATE_PLUMBING = "retired_state_plumbing"
    RETIRED_CORRIDOR = "retired_corridor"


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
            raise ValueError("only semantically excluded paths may carry exclusion IDs")
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
        if self.result_id != authority_id((
            "unflatten.corridor-coverage-phase.v1", self.forecast_id,
            self.phase, self.source_fingerprint, self.candidate_fingerprint,
            self.source_generation, self.candidate_generation,
            self.covered_path_ids, self.residual_path_ids, self.drifted_path_ids,
            self.enumeration_complete, self.matched_semantic_exclusion_ids,
            self.source_dispatcher_reachable, self.candidate_dispatcher_reachable,
        )):
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
            if self.anchor_ea != self.subject.anchor_ea:
                raise ValueError("unique binding anchor must equal subject anchor")
            if self.anchor_ea not in eas:
                raise ValueError("unique binding anchor must belong to native EAs")
        elif (
            self.block_ref is not None
            or self.serial is not None
            or self.anchor_ea is not None
            or eas
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

    def __post_init__(self) -> None:
        _inventory_nonnegative(self.ordinal, "ordinal")
        if self.instruction_ea is not None:
            _inventory_ea(self.instruction_ea, "instruction_ea")
        if type(self.opcode) is not int:
            raise TypeError("opcode must be an exact int")
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
    if len(set(successor_serials)) != len(successor_serials) or successor_serials != tuple(sorted(successor_serials)):
        raise ValueError("successor serials must be sorted and unique")
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
    if block_kind is BlockKind.STOP and not tail_terminal:
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

    def __post_init__(self) -> None:
        _inventory_nonnegative(self.serial, "serial")
        if self.block_ref is not None:
            _cfg_ref(self.block_ref)
        if type(self.block_kind) is not BlockKind:
            raise TypeError("block_kind must be BlockKind")
        if type(self.graph_start_ea) is not int:
            raise TypeError("graph_start_ea must be an exact int")
        if not 0 <= self.graph_start_ea <= _BADADDR:
            raise ValueError("graph_start_ea must be a graph coordinate or BADADDR")
        if self.block_kind is BlockKind.STOP and self.anchor_ea is None:
            raise ValueError("STOP observations require a resolved anchor EA")
        if self.anchor_ea is not None:
            _inventory_ea(self.anchor_ea, "anchor_ea")
        for name in ("native_instruction_eas", "predecessor_serials", "successor_serials"):
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
        if self.transfer_ea is not None:
            _inventory_ea(self.transfer_ea, "transfer_ea")
        if type(self.instruction_observations) is not tuple:
            raise TypeError("instruction_observations must be an exact tuple")
        if any(type(item) is not InventoryInstructionObservation for item in self.instruction_observations):
            raise TypeError("instruction_observations must contain exact rows")
        if tuple(item.ordinal for item in self.instruction_observations) != tuple(range(len(self.instruction_observations))):
            raise ValueError("instruction observations must be contiguous ordinal order")
        observed_eas = {item.instruction_ea for item in self.instruction_observations if item.instruction_ea is not None}
        if self.native_instruction_eas and not self.instruction_observations:
            raise ValueError("native instruction origins require ordered instruction observations")
        if self.instruction_observations and observed_eas != set(self.native_instruction_eas):
            raise ValueError("native_instruction_eas must equal resolved instruction observation EAs")
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

    def __post_init__(self) -> None:
        for name in ("route_subject_id", "atomic_group_id", "source_subject_id"):
            _id(getattr(self, name), name)
        for name in ("proof_ids", "destination_subject_ids"):
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
    retirement_catalog: RetirementAuthorityCatalog | None = None

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
        if self.retirement_catalog is None:
            raise ValueError("retirement claims require an exact retirement catalog")
        else:
            if type(self.retirement_catalog) is not RetirementAuthorityCatalog:
                raise TypeError("retirement_catalog must be RetirementAuthorityCatalog")
            if self.retirement_catalog.source_generation != self.source_generation:
                raise ValueError("retirement catalog generation differs from claim")
            catalog_members = tuple(
                (member.block_ref, member.anchor_ea)
                for member in self.retirement_catalog.members
            )
            if catalog_members != expected_members:
                raise ValueError("retirement catalog must match exact corridor member order")
            retired_members = tuple(
                (member.block_ref, member.anchor_ea)
                for member in self.retirement_catalog.retired_members
            )
            if set(actual_members) != set(retired_members):
                raise ValueError("retirement members must match retired catalog partition")
            catalog_proof_ids = tuple(proof.proof_id for proof in self.retirement_catalog.proofs)
            if proofs != tuple(sorted(catalog_proof_ids)):
                raise ValueError("retirement proof IDs must match closed catalog proofs")
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
        if self.effect_subject != self.discarded_effect_subject:
            raise ValueError("exact effect subject must equal discarded effect subject")
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
class RetirementProofRecord:
    """Closed proof content attached to an exact retirement catalog row.

    The proof ID is derived from the immutable payload digest and its ordered
    member/anchor projection.  Callers therefore cannot mint an arbitrary
    proof identifier and have it treated as retirement authority.
    """

    proof_id: str
    family: RetirementProofFamily
    canonical_payload: bytes
    member_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    member_anchor_eas: tuple[int, ...]
    source_generation: int
    roles: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.proof_id, "proof_id")
        _enum(self.family, RetirementProofFamily, "family")
        if type(self.canonical_payload) is not bytes or not self.canonical_payload:
            raise TypeError("canonical_payload must be non-empty exact bytes")
        try:
            decoded_payload = decode_legacy_value(self.canonical_payload)
        except Exception as exc:
            raise ValueError("canonical_payload must be valid legacy wire bytes") from exc
        if type(decoded_payload) is not dict or set(decoded_payload) != {
            "family", "source_generation", "members", "family_payload",
        }:
            raise ValueError("canonical_payload must be a closed retirement proof envelope")
        if decoded_payload["family"] != self.family.value:
            raise ValueError("retirement proof payload family disagrees with record")
        if decoded_payload["source_generation"] != self.source_generation:
            raise ValueError("retirement proof payload generation disagrees with record")
        raw_members = decoded_payload["members"]
        if type(raw_members) is not tuple:
            raise ValueError("retirement proof payload members must preserve tuple order")
        decoded_members = []
        for raw_member in raw_members:
            if type(raw_member) is not dict or set(raw_member) != {
                "ref", "anchor_ea", "retired", "role",
            }:
                raise ValueError("retirement proof payload member is malformed")
            if type(raw_member["ref"]) is not bytes:
                raise ValueError("retirement proof payload ref is malformed")
            if type(raw_member["anchor_ea"]) is not int or raw_member["anchor_ea"] < 0:
                raise ValueError("retirement proof payload anchor is malformed")
            if type(raw_member["retired"]) is not bool:
                raise ValueError("retirement proof payload retired flag is malformed")
            if type(raw_member["role"]) is not str or not raw_member["role"].strip():
                raise ValueError("retirement proof payload role is malformed")
            try:
                ref = canonical_decode(raw_member["ref"])
            except Exception as exc:
                raise ValueError("retirement proof payload ref is not canonical") from exc
            if type(ref) not in (NativeBlockRef, LogicalBlockRef):
                raise ValueError("retirement proof payload ref is not an authority ref")
            decoded_members.append((ref, raw_member["anchor_ea"], raw_member["retired"], raw_member["role"]))
        if decoded_members != list(zip(self.member_refs, self.member_anchor_eas,
                                       tuple(raw["retired"] for raw in raw_members), self.roles)):
            raise ValueError("retirement proof payload members disagree with record")
        family_payload = decoded_payload["family_payload"]
        if type(family_payload) is not dict or set(family_payload) != {self.family.value}:
            raise ValueError("retirement proof payload family content is malformed")
        raw_rows = family_payload[self.family.value]
        if type(raw_rows) is not tuple or len(raw_rows) != len(decoded_members):
            raise ValueError("retirement proof family rows must preserve exact tuple order")
        for raw_row, (_ref, anchor, retired, role) in zip(raw_rows, decoded_members):
            if type(raw_row) is not dict or set(raw_row) != {"role", "anchor_ea", "retired"}:
                raise ValueError("retirement proof family row is malformed")
            if (
                type(raw_row["role"]) is not str
                or type(raw_row["anchor_ea"]) is not int
                or raw_row["anchor_ea"] < 0
                or type(raw_row["retired"]) is not bool
            ):
                raise ValueError("retirement proof family row has non-canonical fields")
            if (
                raw_row["role"] != role
                or raw_row["anchor_ea"] != anchor
                or raw_row["retired"] != retired
            ):
                raise ValueError("retirement proof family row disagrees with payload member")
        if encode_legacy_value(decoded_payload) != self.canonical_payload:
            raise ValueError("canonical_payload is not byte-canonical")
        if type(self.member_refs) is not tuple:
            raise TypeError("member_refs must be an exact tuple")
        refs = self.member_refs
        if not refs:
            raise ValueError("retirement proof must cover at least one member")
        for ref in refs:
            _authority_ref(ref, "member_refs item")
        if type(self.member_anchor_eas) is not tuple:
            raise TypeError("member_anchor_eas must be an exact tuple")
        anchors = self.member_anchor_eas
        if len(anchors) != len(refs):
            raise ValueError("retirement proof refs and anchors must be one-to-one")
        for anchor in anchors:
            _ea(anchor, "member_anchor_eas item")
        if type(self.roles) is not tuple:
            raise TypeError("roles must be an exact tuple")
        roles = self.roles
        if len(roles) != len(refs) or any(type(role) is not str or not role.strip() for role in roles):
            raise ValueError("retirement proof roles must match ordered members")
        allowed_roles = {
            RetirementProofFamily.RETIRED_INFRASTRUCTURE: {
                "comparison_dispatcher", "comparison_corridor", "dispatcher_feeder", "state_merge",
            },
            RetirementProofFamily.RETIRED_STATE_PLUMBING: {
                "dispatcher_state_feeder", "dispatcher_state_merge", "state_normalizer",
            },
            RetirementProofFamily.RETIRED_CORRIDOR: {"comparison_corridor"},
        }[self.family]
        if any(role not in allowed_roles for role in roles):
            raise ValueError("retirement proof role is not valid for its family")
        _generation(self.source_generation, "source_generation")
        if len(set(refs)) != len(refs):
            raise ValueError("retirement proof member refs must be unique")
        if len(set(anchors)) != len(anchors):
            raise ValueError("retirement proof anchors must be unique")
        object.__setattr__(self, "member_refs", refs)
        object.__setattr__(self, "member_anchor_eas", anchors)
        object.__setattr__(self, "roles", roles)
        expected = authority_id(("unflatten.retirement-proof.v3", self.canonical_payload))
        if self.proof_id != expected:
            raise ValueError("proof_id does not match closed proof content")

    @property
    def content_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_payload).hexdigest()

    @property
    def _decoded_retired_flags(self) -> tuple[bool, ...]:
        decoded = decode_legacy_value(self.canonical_payload)
        rows = decoded["family_payload"][self.family.value]
        return tuple(row["retired"] for row in rows)


@dataclass(frozen=True, slots=True)
class RetirementMemberCatalogRow:
    """One exact plan member, explicitly retired or retained."""

    block_ref: NativeBlockRef | LogicalBlockRef
    anchor_ea: int
    native_instruction_eas: tuple[int, ...]
    source_generation: int
    retired: bool
    proofs: tuple[RetirementProofRecord, ...] = ()

    def __post_init__(self) -> None:
        _authority_ref(self.block_ref, "block_ref")
        _ea(self.anchor_ea, "anchor_ea")
        eas = _tuple(self.native_instruction_eas, "native_instruction_eas")
        if not eas or self.anchor_ea not in eas:
            raise ValueError("retirement row must contain its anchor in native instruction EAs")
        for ea in eas:
            _ea(ea, "native_instruction_eas item")
        _generation(self.source_generation, "source_generation")
        if type(self.retired) is not bool:
            raise TypeError("retired must be an exact bool")
        proofs = _tuple(self.proofs, "proofs", sort=True)
        if any(type(proof) is not RetirementProofRecord for proof in proofs):
            raise TypeError("proofs must contain RetirementProofRecord values")
        if not self.retired and proofs:
            raise ValueError("retained retirement rows cannot carry retirement proofs")
        for proof in proofs:
            if self.block_ref not in proof.member_refs or self.anchor_ea not in proof.member_anchor_eas:
                raise ValueError("retirement proof does not cover its catalog row")
            if proof.source_generation != self.source_generation:
                raise ValueError("retirement proof generation differs from catalog row")
        object.__setattr__(self, "native_instruction_eas", eas)
        object.__setattr__(self, "proofs", proofs)


@dataclass(frozen=True, slots=True)
class RetirementAuthorityCatalog:
    """Canonical, case-owned exact retirement authority."""

    catalog_id: str
    source_generation: int
    members: tuple[RetirementMemberCatalogRow, ...]
    proofs: tuple[RetirementProofRecord, ...]

    def __post_init__(self) -> None:
        _id(self.catalog_id, "catalog_id")
        _generation(self.source_generation, "source_generation")
        members = _tuple(self.members, "members")
        proofs = _tuple(self.proofs, "proofs", sort=True)
        if not members:
            raise ValueError("retirement catalog must not be empty")
        if any(type(member) is not RetirementMemberCatalogRow for member in members):
            raise TypeError("members must contain RetirementMemberCatalogRow values")
        if any(type(proof) is not RetirementProofRecord for proof in proofs):
            raise TypeError("proofs must contain RetirementProofRecord values")
        if any(member.source_generation != self.source_generation for member in members):
            raise ValueError("retirement catalog member generation mismatch")
        if any(proof.source_generation != self.source_generation for proof in proofs):
            raise ValueError("retirement catalog proof generation mismatch")
        refs = tuple(member.block_ref for member in members)
        if len(set(refs)) != len(refs):
            raise ValueError("retirement catalog members must be unique")
        if tuple(sorted(refs, key=canonical_bytes)) != refs:
            raise ValueError("retirement catalog members must use canonical plan order")
        proof_ids = {proof.proof_id for proof in proofs}
        attached = {proof.proof_id for member in members for proof in member.proofs}
        if attached != proof_ids:
            raise ValueError("retirement catalog proof partition is not exact")
        covered_refs = {ref for proof in proofs for ref in proof.member_refs}
        if covered_refs != set(refs):
            raise ValueError("retirement catalog proofs must cover every plan member")
        decoded_partition: dict[NativeBlockRef | LogicalBlockRef, bool] = {}
        for proof in proofs:
            expected_proof_order = tuple(ref for ref in refs if ref in proof.member_refs)
            if proof.member_refs != expected_proof_order:
                raise ValueError("retirement proof members must preserve catalog order")
            for ref, retired in zip(proof.member_refs, proof._decoded_retired_flags):
                if ref in decoded_partition:
                    raise ValueError("retirement proof partition contains duplicate members")
                decoded_partition[ref] = retired
        expected_partition = {member.block_ref: member.retired for member in members}
        if decoded_partition != expected_partition:
            raise ValueError("retirement proof partition does not equal catalog retirement flags")
        expected = authority_id((
            "unflatten.retirement-catalog.v1", self.source_generation,
            members, proofs,
        ))
        if self.catalog_id != expected:
            raise ValueError("catalog_id does not match exact retirement catalog")

    @property
    def retired_members(self) -> tuple[RetirementMemberCatalogRow, ...]:
        return tuple(member for member in self.members if member.retired)

    @property
    def retained_members(self) -> tuple[RetirementMemberCatalogRow, ...]:
        return tuple(member for member in self.members if not member.retired)


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
    retirement_catalog: RetirementAuthorityCatalog | None = None
    corridor_coverage_forecast: CorridorCoverageForecast | None = None

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
        if self.retirement_catalog is not None and type(self.retirement_catalog) is not RetirementAuthorityCatalog:
            raise TypeError("retirement_catalog must be RetirementAuthorityCatalog or None")
        if self.corridor_coverage_forecast is not None:
            if type(self.corridor_coverage_forecast) is not CorridorCoverageForecast:
                raise TypeError("corridor_coverage_forecast must be CorridorCoverageForecast or None")
            self.corridor_coverage_forecast.__post_init__()
            forecast = self.corridor_coverage_forecast
            if forecast.semantic_exclusions or any(
                path.disposition is CorridorPathDisposition.SEMANTICALLY_EXCLUDED
                for path in forecast.paths
            ):
                raise ValueError("semantic exclusion corridor authority is reserved for Task15")
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
        requires_corridor_forecast = (
            self.retirement_catalog is not None
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
                    if witness is None:
                        raise ValueError("proposal subject reference is absent from source catalog")
                    if anchor is not None and witness.anchor_ea != anchor:
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
        retired_refs = {
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
            catalogs = tuple(claim.retirement_catalog for claim in retirement_claims)
            if self.retirement_catalog is None or any(catalog != self.retirement_catalog for catalog in catalogs):
                raise ValueError("retirement claims must share the proposal-owned catalog")
            if set(retired_refs) != {
                member.block_ref for member in self.retirement_catalog.retired_members
            }:
                raise ValueError("proposal retirement partition disagrees with catalog")
            if {
                member.block_ref for member in self.retirement_catalog.members
            } != dispatcher_member_refs:
                raise ValueError("proposal retirement catalog is not exact plan membership")
            for member in self.retirement_catalog.members:
                witness = catalog_by_ref.get(member.block_ref)
                if witness is None or (
                    member.anchor_ea != witness.anchor_ea
                    or member.native_instruction_eas != witness.native_instruction_eas
                ):
                    raise ValueError("retirement catalog native identity drifted")
        elif self.retirement_catalog is not None:
            raise ValueError("proposal retirement catalog has no retirement claim")
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
}
_LOSS_RULE_CLAIMS = {
    UnflattenJustificationRule.RETIRED_INFRASTRUCTURE_PROVEN: (RetiredDispatcherInfrastructureClaim,),
    UnflattenJustificationRule.EQUIVALENT_ROUTE_PROVEN: (EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim),
    UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN: (ExactInfeasibleEffectClaim,),
    UnflattenJustificationRule.TERMINAL_CYCLE_BREAK_PROVEN: (TerminalCycleBreakClaim,),
    UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN: (LocalAliasEffectScalarizationClaim,),
}


@dataclass(frozen=True, slots=True)
class SemanticLossRow:
    """One evaluator-owned projection of a source subject that is missing."""

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
        self.case.__post_init__()
        if self.case.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("semantic loss rows require a projected or observed case")
        if type(self.source_subject) is not SemanticSubjectRef:
            raise TypeError("source_subject must be a SemanticSubjectRef")
        source_subject_ids = set(self.case.source_subject_ids)
        if self.source_subject.subject_id not in source_subject_ids:
            raise ValueError("loss row subject must belong to the case source partition")
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
        if self.candidate_binding.status is not SubjectBindingStatus.MISSING:
            raise ValueError("semantic loss rows require a missing candidate binding")
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
            cell.key.subject != self.source_subject
            or cell.key.dimension is SafetyDimension.STRUCTURAL_ACCOUNTING
            or cell.phase is not self.candidate_binding.phase
            for cell in semantic
        ):
            raise ValueError("semantic obligation cells must be same-subject non-structural cells")
        if semantic != tuple(sorted(semantic, key=lambda cell: cell.key.dimension.value)):
            raise ValueError("relevant semantic obligations must be in canonical order")
        if len({cell.key.dimension for cell in semantic}) != len(semantic):
            raise ValueError("relevant semantic obligations must be unique")
        expected_semantic = tuple(
            cell for cell in self.case.obligation_index.cells
            if cell.key.subject == self.source_subject
            and cell.key.dimension is not SafetyDimension.STRUCTURAL_ACCOUNTING
        )
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
            RetiredDispatcherInfrastructureClaim, EquivalentSemanticRouteClaim,
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
        if len(kinds) != 1:
            return SemanticLossKind.CONFLICTING if len(kinds) > 1 else SemanticLossKind.UNCLASSIFIED
        return next(iter(kinds))

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

    def __post_init__(self) -> None:
        if type(self.case) is not SemanticSafetyCase:
            raise TypeError("case must be a SemanticSafetyCase")
        self.case.__post_init__()
        _id(self.authority_id, "authority_id")
        _id(self.case_id, "case_id")
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.candidate_fingerprint, "candidate_fingerprint")
        if type(self.rows) is not tuple:
            raise TypeError("rows must be an exact tuple")
        if any(type(row) is not SemanticLossRow for row in self.rows):
            raise TypeError("rows must contain SemanticLossRow values")
        if any(row.case != self.case for row in self.rows):
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
    rows: tuple[SemanticLossRow, ...]

    def __post_init__(self) -> None:
        _id(self.authority_id, "authority_id")
        _id(self.source_fingerprint, "source_fingerprint")
        _id(self.projected_case_id, "projected_case_id")
        _id(self.observed_case_id, "observed_case_id")
        if type(self.rows) is not tuple:
            raise TypeError("rows must be an exact tuple")
        if any(type(row) is not SemanticLossRow for row in self.rows):
            raise TypeError("rows must contain SemanticLossRow values")
        if self.rows != tuple(sorted(self.rows, key=lambda row: row.source_subject.subject_id)):
            raise ValueError("rows must be in source subject order")
        if len({row.source_subject.subject_id for row in self.rows}) != len(self.rows):
            raise ValueError("rows must contain unique source subjects")

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

    @property
    def serial_by_ref(self) -> dict[CfgBlockRef, int]:
        """Project the closed block rows into the source-ref index."""

        return {
            block.block_ref: block.serial
            for block in self.blocks
            if block.block_ref is not None
        }

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
        if tuple(sorted(expected_reachable)) != reachable_serials:
            raise ValueError("reachable_serials must equal the raw successor closure")
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
            item.block_ref is None or item.anchor_ea is None for item in self.blocks
        ):
            raise ValueError("producer observations require mapped block identities and anchors")
        if self.phase is UnflattenAuthorityPhase.PRODUCER_FORECAST and any(
            item.anchor_ea not in item.native_instruction_eas for item in self.blocks
        ):
            raise ValueError("producer anchors must belong to native instruction origins")
        for block in self.blocks:
            if type(block.block_ref) is NativeBlockRef:
                identity = block.block_ref.identity
                if identity.exact_instruction_eas != frozenset(block.native_instruction_eas):
                    raise ValueError("native identity instruction EAs do not match block row")
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
                if (
                    binding.block_ref != block.block_ref
                    or binding.anchor_ea != block.anchor_ea
                    or binding.native_instruction_eas != block.native_instruction_eas
                ):
                    raise ValueError("unique binding does not match its block observation")
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
        )
        if self.inventory_digest != expected:
            raise ValueError("inventory_digest does not match inventory content")


def validate_semantic_graph_inventory(value: object) -> SemanticGraphInventory:
    """Revalidate a live inventory object before every authority consumption."""

    if type(value) is not SemanticGraphInventory:
        raise TypeError("inventory must be SemanticGraphInventory")
    value.__post_init__()
    return value


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
    metrics: PreparationBuildMetrics
    generic_gate_facts_digest: str | None = None
    route_assessment_digest: str | None = None
    retirement_catalog: RetirementAuthorityCatalog | None = None
    corridor_coverage_forecast: CorridorCoverageForecast | None = None
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
        for name in ("generic_gate_facts_digest", "route_assessment_digest"):
            value = getattr(self, name)
            if value is not None:
                _id(value, name)
        if self.retirement_catalog is not None and type(self.retirement_catalog) is not RetirementAuthorityCatalog:
            raise TypeError("retirement_catalog must be RetirementAuthorityCatalog or None")
        if self.corridor_coverage_forecast is not None:
            if type(self.corridor_coverage_forecast) is not CorridorCoverageForecast:
                raise TypeError("corridor_coverage_forecast must be CorridorCoverageForecast or None")
            self.corridor_coverage_forecast.__post_init__()
            if self.corridor_coverage_forecast.plan_id != self.plan_id:
                raise ValueError("receipt corridor forecast belongs to a foreign plan")
            if self.corridor_coverage_forecast.source_generation != self.source_generation:
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
                "conditional_relation_digest", "metrics",
                "generic_gate_facts_digest", "route_assessment_digest", "retirement_catalog",
                "corridor_coverage_forecast",
            )
        }
        for name in ("generic_gate_facts_digest", "route_assessment_digest"):
            if name in values:
                if values[name] is not None:
                    _id(values[name], name)
            else:
                values[name] = None
        values.setdefault("retirement_catalog", None)
        values.setdefault("corridor_coverage_forecast", None)
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


@dataclass(frozen=True, slots=True)
class UnflattenPhaseDiagnosticContext:
    """Complete typed context for one phase observation.

    Diagnostics consume this value as a projection only; it is never an
    authority input and contains no live SDK object or duck-typed payload.
    """

    plan_id: str
    attempt_id: TransactionAttemptId | None
    rule_set_version: int
    schema_version: int
    snapshot_id: str
    maturity: str
    source_fingerprint: str | None
    candidate_fingerprint: str | None
    authority_id: str | None
    binding_id: str | None
    case_id: str | None
    phase: UnflattenAuthorityPhase
    obligation_states: tuple[ObligationEvidenceCell, ...]
    loss_rows: tuple[tuple[str, int, int | None], ...]
    handler_summary: tuple[str, ...]
    terminal_summary: tuple[str, ...]
    coverage_summary: tuple[str, ...]
    phase_metrics: SemanticPhaseMetrics | None

    def __post_init__(self) -> None:
        _text(self.plan_id, "plan_id")
        if self.attempt_id is not None and type(self.attempt_id) is not TransactionAttemptId:
            raise TypeError("attempt_id must be TransactionAttemptId or None")
        if type(self.rule_set_version) is not int or self.rule_set_version < 1:
            raise ValueError("rule_set_version must be positive")
        if type(self.schema_version) is not int or self.schema_version < 1:
            raise ValueError("schema_version must be positive")
        _text(self.snapshot_id, "snapshot_id")
        _text(self.maturity, "maturity")
        for name in ("source_fingerprint", "candidate_fingerprint", "authority_id", "binding_id", "case_id"):
            value = getattr(self, name)
            if value is not None:
                _id(value, name)
        _enum(self.phase, UnflattenAuthorityPhase, "phase")
        states = _tuple(self.obligation_states, "obligation_states")
        if any(type(value) is not ObligationEvidenceCell for value in states):
            raise TypeError("obligation_states must contain ObligationEvidenceCell values")
        object.__setattr__(self, "obligation_states", states)
        rows = _tuple(self.loss_rows, "loss_rows")
        for row in rows:
            if type(row) is not tuple or len(row) != 3 or type(row[0]) is not str or type(row[1]) is not int:
                raise TypeError("loss_rows must contain (label, serial, ea) rows")
            if row[1] < 0 or (row[2] is not None and (type(row[2]) is not int or row[2] < 0)):
                raise ValueError("loss row coordinates must be non-negative")
        object.__setattr__(self, "loss_rows", rows)
        for name in ("handler_summary", "terminal_summary", "coverage_summary"):
            values = _tuple(getattr(self, name), name, sort=True)
            if any(type(value) is not str for value in values):
                raise TypeError(f"{name} must contain strings")
            object.__setattr__(self, name, values)
        if self.phase_metrics is not None and type(self.phase_metrics) is not SemanticPhaseMetrics:
            raise TypeError("phase_metrics must be SemanticPhaseMetrics or None")


@dataclass(frozen=True, slots=True)
class DerivedUnflattenPreparationInputs:
    proposal: ProposedUnflattenContract
    claims: tuple[UnflattenClaim, ...]
    preparation_receipt: PreparationAuthorityReceipt
    source_inventory: SemanticGraphInventory
    candidate_inventory: SemanticGraphInventory
    source_route_assessment: CanonicalRouteAssessment | None
    candidate_route_assessment: CanonicalRouteAssessment | None
    generic_gate_facts: GenericCfgGateFacts | None
    conditional_relations: tuple[ConditionalSubjectRelation, ...]
    patch_step_facts: tuple[PatchStepEvidencePayload, ...]
    preparation_metrics: PreparationBuildMetrics
    phase_build_metrics: PhaseBuildMetrics
    corridor_coverage_phase_result: CorridorCoveragePhaseResult | None = None

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
        for name in ("source_inventory", "candidate_inventory"):
            inventory = getattr(self, name)
            if type(inventory) is not SemanticGraphInventory:
                raise TypeError(f"{name} must be SemanticGraphInventory")
            validate_semantic_graph_inventory(inventory)
        forecast = self.proposal.corridor_coverage_forecast
        if forecast is not None and not (
            forecast.function_ea == self.source_inventory.function_ea
            and forecast.function_ea == self.candidate_inventory.function_ea
        ):
            raise ValueError("corridor forecast function EA is not sealed to both inventories")
        if self.candidate_inventory.source_subject_ids != self.source_inventory.source_subject_ids:
            raise ValueError(
                "candidate source subject partition must equal source inventory partition"
            )
        for name in ("source_route_assessment", "candidate_route_assessment"):
            assessment = getattr(self, name)
            if assessment is not None:
                if type(assessment) is not CanonicalRouteAssessment:
                    raise TypeError(f"{name} must be CanonicalRouteAssessment or None")
                validate_canonical_route_assessment(assessment)
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
            if type(self.corridor_coverage_phase_result) is not CorridorCoveragePhaseResult:
                raise TypeError("corridor_coverage_phase_result must be CorridorCoveragePhaseResult or None")
            result = self.corridor_coverage_phase_result
            result.__post_init__()
            if forecast is None or result.forecast_id != forecast.forecast_id:
                raise ValueError("corridor phase result is foreign to the proposal forecast")
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
        has_retirement = any(
            type(claim) is RetiredDispatcherInfrastructureClaim for claim in self.claims
        )
        if has_retirement:
            if self.proposal.retirement_catalog is None or self.preparation_receipt.retirement_catalog != self.proposal.retirement_catalog:
                raise ValueError("retirement preparation records must share the exact catalog")
        elif self.proposal.retirement_catalog is not None or self.preparation_receipt.retirement_catalog is not None:
            raise ValueError("retirement catalog is present without a retirement claim")
        if self.preparation_receipt.corridor_coverage_forecast != self.proposal.corridor_coverage_forecast:
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
        if self.source_route_assessment is not None:
            if (
                self.source_route_assessment.phase is not CanonicalRouteAssessmentPhase.SOURCE
                or self.source_route_assessment.graph_fingerprint != source_fingerprint
                or self.source_route_assessment.generation != source_generation
                or self.source_route_assessment.evidence is not self.proposal.route_evidence
            ):
                raise ValueError("source route assessment does not match source authority")
        if self.candidate_route_assessment is not None:
            if (
                self.candidate_route_assessment.phase is not {
                    UnflattenAuthorityPhase.PROJECTED_PREFLIGHT: CanonicalRouteAssessmentPhase.PROJECTED,
                    UnflattenAuthorityPhase.OBSERVED_POST_APPLY: CanonicalRouteAssessmentPhase.OBSERVED,
                }.get(self.phase_build_metrics.phase)
                or self.candidate_route_assessment.graph_fingerprint != candidate_fingerprint
                or self.candidate_route_assessment.generation != candidate_generation
                or self.candidate_route_assessment.evidence is not self.proposal.route_evidence
            ):
                raise ValueError("candidate route assessment does not match candidate authority")
        if self.preparation_receipt.source_inventory_digest != self.source_inventory.inventory_digest:
            raise ValueError("receipt source inventory digest does not match inventory")
        if self.preparation_receipt.candidate_inventory_digest != self.candidate_inventory.inventory_digest:
            raise ValueError("receipt candidate inventory digest does not match inventory")


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
    source_subject_ids: tuple[str, ...] = ()
    source_bindings: tuple[PhaseSubjectBinding, ...] = ()
    retirement_catalog: RetirementAuthorityCatalog | None = None
    corridor_coverage_phase_result: CorridorCoveragePhaseResult | None = None

    def __post_init__(self) -> None:
        _id(self.case_id, "case_id")
        _id(self.authority_id, "authority_id")
        _id(self.preparation_receipt_id, "preparation_receipt_id")
        if type(self.preparation_receipt) is not PreparationAuthorityReceipt:
            raise TypeError("preparation_receipt must be PreparationAuthorityReceipt")
        PreparationAuthorityReceipt.__post_init__(self.preparation_receipt)
        validate_semantic_graph_inventory(self.source_inventory)
        forecast = self.preparation_receipt.corridor_coverage_forecast
        if forecast is not None and forecast.function_ea != self.source_inventory.function_ea:
            raise ValueError("case corridor forecast function EA differs from source inventory")
        if self.retirement_catalog is not None and type(self.retirement_catalog) is not RetirementAuthorityCatalog:
            raise TypeError("retirement_catalog must be RetirementAuthorityCatalog or None")
        if self.corridor_coverage_phase_result is not None:
            if type(self.corridor_coverage_phase_result) is not CorridorCoveragePhaseResult:
                raise TypeError("corridor_coverage_phase_result must be CorridorCoveragePhaseResult or None")
            self.corridor_coverage_phase_result.__post_init__()
            if forecast is None or self.corridor_coverage_phase_result.forecast_id != forecast.forecast_id:
                raise ValueError("case corridor phase result is foreign to receipt forecast")
            result = self.corridor_coverage_phase_result
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
        has_retirement = any(
            type(claim) is RetiredDispatcherInfrastructureClaim for claim in self.claims
        )
        if has_retirement:
            if self.retirement_catalog is None or self.preparation_receipt.retirement_catalog != self.retirement_catalog:
                raise ValueError("retirement case records must share the exact catalog")
        elif self.retirement_catalog is not None or self.preparation_receipt.retirement_catalog is not None:
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
    source_inventory: SemanticGraphInventory
    source_inputs: DerivedUnflattenPreparationInputs | None = None
    preparation_attempt_id: TransactionAttemptId | None = None
    legacy_unflatten_shadow: LegacyUnflattenShadowEnvelope | None = None
    source_route_assessment: CanonicalRouteAssessment | None = None
    projected_route_assessment: CanonicalRouteAssessment | None = None

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
        if type(self.bound_routes) is not BoundCanonicalSemanticEvidence:
            raise TypeError("bound_routes must be BoundCanonicalSemanticEvidence")
        for name in ("source_route_assessment", "projected_route_assessment"):
            assessment = getattr(self, name)
            if assessment is not None:
                if type(assessment) is not CanonicalRouteAssessment:
                    raise TypeError(f"{name} must be CanonicalRouteAssessment or None")
                validate_canonical_route_assessment(assessment)
                if not assessment.accepted:
                    raise ValueError(f"{name} must be an accepted assessment")
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
        if type(self.source_inventory) is not SemanticGraphInventory:
            raise TypeError("source_inventory must be SemanticGraphInventory")
        validate_semantic_graph_inventory(self.source_inventory)
        if self.source_inventory.phase is not UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("prepared source inventory must be producer forecast")
        if self.source_inputs is not None and type(self.source_inputs) is not DerivedUnflattenPreparationInputs:
            raise TypeError("source_inputs must be DerivedUnflattenPreparationInputs or None")
        if self.source_inputs is not None:
            DerivedUnflattenPreparationInputs.__post_init__(self.source_inputs)
            if self.source_route_assessment is not self.source_inputs.source_route_assessment:
                raise ValueError("prepared source route assessment must be the exact input object")
            if self.projected_route_assessment is not self.source_inputs.candidate_route_assessment:
                raise ValueError("prepared projected route assessment must be the exact input object")
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
        if self.source_route_assessment is not None:
            if (
                self.source_route_assessment.phase is not CanonicalRouteAssessmentPhase.SOURCE
                or self.source_route_assessment.graph_fingerprint != self.source_fingerprint
                or self.source_route_assessment.generation != self.source_generation
                or self.source_route_assessment.evidence is not self.proposal.route_evidence
            ):
                raise ValueError("prepared source route assessment does not match authority")
        if self.projected_route_assessment is not None:
            if (
                self.projected_route_assessment.phase is not CanonicalRouteAssessmentPhase.PROJECTED
                or self.projected_route_assessment.graph_fingerprint != self.projected_fingerprint
                or self.projected_route_assessment.generation != self.projected_generation
                or self.projected_route_assessment.evidence is not self.proposal.route_evidence
            ):
                raise ValueError("prepared projected route assessment does not match authority")
        if self.preparation_attempt_id is not None and type(self.preparation_attempt_id) is not TransactionAttemptId:
            raise TypeError("preparation_attempt_id must be TransactionAttemptId or None")
        owning_shadow = getattr(self.owning_plan, "legacy_unflatten_shadow", None)
        if self.legacy_unflatten_shadow is not owning_shadow:
            raise ValueError("prepared shadow must be the owning plan shadow object")
        if self.legacy_unflatten_shadow is not None:
            if type(self.legacy_unflatten_shadow) is not LegacyUnflattenShadowEnvelope:
                raise TypeError("legacy_unflatten_shadow must be LegacyUnflattenShadowEnvelope or None")
            LegacyUnflattenShadowEnvelope.__post_init__(self.legacy_unflatten_shadow)
            if self.legacy_unflatten_shadow.plan_id != self.owning_plan.plan_id:
                raise ValueError("prepared shadow plan does not match owning plan")
            if self.legacy_unflatten_shadow.snapshot_id != self.owning_plan.snapshot_id:
                raise ValueError("prepared shadow snapshot does not match owning plan")
            if self.owning_plan.source_generation is not None and self.legacy_unflatten_shadow.source_generation != self.owning_plan.source_generation:
                raise ValueError("prepared shadow generation does not match owning plan")
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
        def coordinate_key(item: tuple[object, int]) -> tuple[str, int]:
            return repr(item[0]), item[1]
        # PatchPlan.source_coordinates are always authoritative ref -> source
        # serial rows. The catalog anchor is a separate native identity
        # witness and must never be compared to the graph serial.
        plan_coordinates = dict(self.owning_plan.source_coordinates)
        expected_coordinates = tuple(sorted(
            ((block.block_ref, plan_coordinates[block.block_ref])
             for block in self.proposal.source_identity_catalog.blocks),
            key=coordinate_key,
        ))
        if tuple(sorted(self.owning_plan.source_coordinates, key=coordinate_key)) != expected_coordinates:
            raise ValueError("owning plan source coordinates do not match the proposal catalog")
        if self.source_coordinate_digest != authority_id(expected_coordinates):
            raise ValueError("source coordinate digest does not match the proposal catalog")
        source_binding_coordinates = tuple(sorted(
            ((binding.block_ref, binding.serial)
             for binding in self.source_bindings
             if binding.status is SubjectBindingStatus.UNIQUE
             and binding.block_ref is not None and binding.serial is not None),
            key=coordinate_key,
        ))
        if frozenset(source_binding_coordinates) != frozenset(expected_coordinates):
            raise ValueError("source bindings do not cover the proposal catalog")
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
    patch_binding: BoundPatchPlan

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
        if type(self.patch_binding) is not BoundPatchPlan:
            raise TypeError("patch_binding must be BoundPatchPlan")
        validate_bound_patch_plan(self.patch_binding)
        if self.patch_binding.plan is not self.prepared.owning_plan:
            raise ValueError("patch binding plan does not match prepared authority")
        if self.patch_binding.plan.unflatten_proposal is not self.prepared.proposal:
            raise ValueError("patch binding proposal does not match prepared authority")
        if (
            self.patch_binding.plan.legacy_unflatten_shadow
            is not self.prepared.legacy_unflatten_shadow
        ):
            raise ValueError("patch binding shadow does not match prepared authority")
        if self.patch_binding.attempt_id is not self.attempt_id:
            raise ValueError("patch binding attempt does not match authority")
        if (
            self.patch_binding.session_id != self.session_id
            or self.patch_binding.generation != self.generation
        ):
            raise ValueError("patch binding session/generation does not match authority")
        if self.patch_binding.maturity is not self.live_maturity:
            raise ValueError("patch binding maturity does not match authority")
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
