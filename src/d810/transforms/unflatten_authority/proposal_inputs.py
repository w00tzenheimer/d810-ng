"""Explicit owned proposal input values; capture conveys no validation authority.

This family covers explicit non-route proposal input descendants.
Materialization uses
its existing constructors; complete proposal roundtrip checks remain mandatory.
"""

from dataclasses import fields
from types import MappingProxyType

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.structural_identity import StructuralIdentityError
from d810.core.structural_identity import StructuralNodeKind as Kind
from d810.core.structural_identity import StructuralRef, StructuralTable
from d810.ir.block_identity import (
    NativeBlockRef, NativeEaInterval, NativeEaIntervalSet, StableBlockIdentity,
)
from d810.ir.structural_identity import NATIVE_KEY_FIELDS
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import LogicalBlockRef, PlanBlockRef
from d810.transforms.unflatten_authority.model import (
    SourceBlockIdentityWitness, SourceIdentityCatalog, UseDefFragmentWitness,
    RetiredDispatcherInfrastructureClaim, DetachedDeadHandlerComponentClaim, ExactInfeasibleEffectClaim, HandlerSubjectLocator, EffectSubjectLocator, ProviderConsensusWitness, EffectSiteKind, ProviderConsensusMode, SemanticEdgeRole,
    TerminalCycleBreakClaim, TerminalSubjectLocator, CorridorSubjectLocator, TerminalKind,
    EquivalentSemanticRouteClaim, SemanticSubjectRef, SemanticSubjectKind,
    SemanticSubjectRole, UnflattenClaimKind, BlockSubjectLocator,
    RouteSubjectLocator, LogicalFunctionExitSubjectLocator,
    UnflattenPlanInputCatalog, UnflattenPlanShape, AuthoritativeHandlerInput,
    CorridorCoverageForecast, CorridorCoveragePath, CorridorCoveragePathNode,
    CorridorSemanticExclusion, CorridorPathDisposition,
    DefaultGapInfeasibilityForecast, DefaultGapInfeasibilityPath,
    DefaultGapInfeasibilityExclusion, DefaultGapInitialStateSeed,
    RetirementCandidateCatalog, RetirementPlanMember, DispatcherRetirementCandidate,
    EntryEndpointLivenessAllowance, EntryEndpointLivenessReason,
)


_SOURCE_FIELDS = MappingProxyType({
    RetiredDispatcherInfrastructureClaim: ('claim_id', 'kind', 'infrastructure_subject', 'corridor_subject', 'member_subjects', 'candidate_evidence_ids', 'source_generation', 'candidate_catalog'),
    DetachedDeadHandlerComponentClaim: ('claim_id', 'kind', 'dispatcher_subject', 'dead_handler_subjects', 'retained_handler_subjects', 'component_subjects', 'comparison_region_subjects', 'source_generation'),
    ExactInfeasibleEffectClaim: ('claim_id', 'kind', 'effect_subject', 'source_subject', 'predicate_subject', 'selected_target_subject', 'discarded_effect_subject', 'normalized_state', 'state_identity', 'width', 'source_write_ea', 'predicate_branch_ea', 'discarded_effect_ea', 'selected_edge_role', 'route_proof_ids', 'consensus', 'source_generation'),
    HandlerSubjectLocator: ('block_ref', 'anchor_ea', 'normalized_states'),
    EffectSubjectLocator: ('owner_ref', 'owner_anchor_ea', 'instruction_ea', 'effect_kind'),
    ProviderConsensusWitness: ('mode', 'provider_ids'),
    TerminalCycleBreakClaim: (
        "claim_id", "kind", "cycle_subject", "cleanup_source_subject", "terminal_subject",
        "terminal_route_proof_ids", "source_generation",
    ),
    TerminalSubjectLocator: ("block_ref", "anchor_ea", "terminal_kind", "instruction_ea"),
    CorridorSubjectLocator: (
        "corridor_id", "entry_ref", "entry_anchor_ea", "member_refs", "member_anchor_eas",
    ),
    EquivalentSemanticRouteClaim: (
        "claim_id", "kind", "retired_route_subject", "replacement_route_subject",
        "source_subject", "destination_subjects", "route_proof_ids", "atomic_group_id",
        "source_generation", "dag_endpoint_subjects",
    ),
    SemanticSubjectRef: ("kind", "role", "subject_id", "block_ref", "anchor_ea", "locator"),
    BlockSubjectLocator: ("block_ref", "anchor_ea"),
    LogicalFunctionExitSubjectLocator: ("block_ref", "serial"),
    RouteSubjectLocator: (
        "proof_id", "atomic_group_id", "source_ref", "source_anchor_ea",
        "destination_locators", "dag_endpoint_locators",
    ),
    SourceIdentityCatalog: ("native_key", "generation", "blocks"),
    RetirementPlanMember: ("block_ref", "anchor_ea", "native_instruction_eas"),
    DispatcherRetirementCandidate: (
        "block_ref", "anchor_ea", "role", "evidence_ids", "source_generation", "candidate_id",
    ),
    RetirementCandidateCatalog: (
        "catalog_id", "source_generation", "plan_members", "candidates",
    ),
    EntryEndpointLivenessAllowance: (
        "allowance_id", "reason", "normalized_state", "route_proof_id",
        "entry_predecessor_owner_refs", "dispatcher_old_target_ref",
        "replacement_endpoint_ref", "exit_path_refs", "patch_step_index",
        "patch_step_digest", "state_write_source_ref", "state_write_instruction_ea",
        "delivery_path_refs", "delivery_path_edges", "cut_exit_path_uses",
    ),
    PlanBlockRef: ("plan_id", "local_block_id"),
    CorridorCoveragePathNode: ("block_ref", "anchor_ea"),
    DefaultGapInitialStateSeed: ("normalized_state", "route_proof_id"),
    DefaultGapInfeasibilityPath: ("path_id", "nodes", "state_merge", "exclusion_id"),
    DefaultGapInfeasibilityExclusion: (
        "exclusion_id", "digest", "state_width_bytes", "state_identity", "dispatcher",
        "default_entry", "residual", "initial_state_seeds", "route_proof_ids",
        "normalized_reachable_states",
    ),
    DefaultGapInfeasibilityForecast: (
        "extension_id", "base_forecast", "paths", "exclusion_digests", "exclusions",
    ),
    CorridorCoveragePath: (
        "path_id", "nodes", "state_merge", "disposition", "semantic_exclusion_ids",
    ),
    CorridorSemanticExclusion: (
        "exclusion_id", "digest", "normalized_state", "state_identity", "source",
        "feeder", "prefix", "root",
    ),
    CorridorCoverageForecast: (
        "forecast_id", "plan_id", "function_ea", "source_native_key",
        "source_generation", "dispatcher_ref", "dispatcher_anchor_ea", "paths",
        "covered_path_ids", "residual_path_ids", "enumeration_complete",
        "semantic_exclusion_digests", "semantic_exclusions", "semantic_exclusion_path_ids",
    ),
    SourceBlockIdentityWitness: (
        "block_ref", "anchor_ea", "native_instruction_eas",
    ),
    NativePreanalysisKey: NATIVE_KEY_FIELDS,
    NativeBlockRef: ("identity",),
    LogicalBlockRef: ("session_id", "proxy_token", "version"),
    StableBlockIdentity: ("native_key", "exact_instruction_eas", "native_ranges"),
    NativeEaIntervalSet: ("intervals",),
    NativeEaInterval: ("start_ea", "end_ea"),
    StorageIdentity: ("kind", "offset"),
    UnflattenPlanInputCatalog: (
        "shape", "source_entry_ref", "dispatcher_entry_ref", "dispatcher_member_refs",
        "authoritative_handlers", "state_identity",
    ),
    AuthoritativeHandlerInput: ("block_ref", "anchor_ea", "normalized_states"),
    UseDefFragmentWitness: (
        "fragment_id", "state_identity", "redirect_owner_refs", "redirect_digest",
        "executed", "fragment_atomic", "actionable_non_state_severance_count",
        "violation_ids",
    ),
})
_SOURCE_TYPES = MappingProxyType({
    (kind.__module__, kind.__qualname__): kind for kind in _SOURCE_FIELDS
})

_SOURCE_ENUMS = MappingProxyType({
    (EffectSiteKind.__module__, EffectSiteKind.__qualname__): EffectSiteKind,
    (ProviderConsensusMode.__module__, ProviderConsensusMode.__qualname__): ProviderConsensusMode,
    (SemanticEdgeRole.__module__, SemanticEdgeRole.__qualname__): SemanticEdgeRole,
    (TerminalKind.__module__, TerminalKind.__qualname__): TerminalKind,
    (SemanticSubjectKind.__module__, SemanticSubjectKind.__qualname__): SemanticSubjectKind,
    (SemanticSubjectRole.__module__, SemanticSubjectRole.__qualname__): SemanticSubjectRole,
    (UnflattenClaimKind.__module__, UnflattenClaimKind.__qualname__): UnflattenClaimKind,
    (StorageIdentityKind.__module__, StorageIdentityKind.__qualname__): StorageIdentityKind,
    (UnflattenPlanShape.__module__, UnflattenPlanShape.__qualname__): UnflattenPlanShape,
    (CorridorPathDisposition.__module__, CorridorPathDisposition.__qualname__): CorridorPathDisposition,
    (EntryEndpointLivenessReason.__module__, EntryEndpointLivenessReason.__qualname__): EntryEndpointLivenessReason,
})

_DERIVED_FIELDS = MappingProxyType({
    RetiredDispatcherInfrastructureClaim: ("claim_id",),
    DetachedDeadHandlerComponentClaim: ("claim_id",),
    ExactInfeasibleEffectClaim: ("claim_id",),
    CorridorCoveragePath: ("path_id",),
    TerminalCycleBreakClaim: ("claim_id",),
    EquivalentSemanticRouteClaim: ("claim_id",),
    SemanticSubjectRef: ("subject_id",),
})
# These exact fields are also excluded by the canonical codec. They are never
# read, interned, or restored; reconstruction receives constructor defaults.
_RUNTIME_FIELDS = MappingProxyType({
    EquivalentSemanticRouteClaim: ("_runtime_refs",),
    SemanticSubjectRef: ("_runtime_ref",),
})


_PRODUCER_CLAIM_TYPES = (
    RetiredDispatcherInfrastructureClaim, DetachedDeadHandlerComponentClaim,
    EquivalentSemanticRouteClaim, ExactInfeasibleEffectClaim, TerminalCycleBreakClaim,
)


def capture_producer_claim(table: StructuralTable, value: object) -> StructuralRef:
    """Detach only the exact producer union, never transaction-derived claims."""
    if type(table) is not StructuralTable or type(value) not in _PRODUCER_CLAIM_TYPES:
        raise TypeError("producer claim capture requires exact table and producer claim")
    return _capture(table, value, set())


def materialize_producer_claim(table: StructuralTable, ref: StructuralRef) -> object:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("producer claim read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if _SOURCE_TYPES.get(node.payload) not in _PRODUCER_CLAIM_TYPES:
        raise StructuralIdentityError("handle does not identify a producer claim")
    return _materialize(table, ref)


def capture_terminal_claim(table: StructuralTable, value: TerminalCycleBreakClaim) -> StructuralRef:
    if type(table) is not StructuralTable or type(value) is not TerminalCycleBreakClaim:
        raise TypeError("terminal claim capture requires exact table and record")
    return _capture(table, value, set())


def materialize_terminal_claim(table: StructuralTable, ref: StructuralRef) -> TerminalCycleBreakClaim:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("terminal claim read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (TerminalCycleBreakClaim.__module__, TerminalCycleBreakClaim.__qualname__):
        raise StructuralIdentityError("handle does not identify a terminal claim")
    return _materialize(table, ref)


def capture_route_claim(table: StructuralTable, value: EquivalentSemanticRouteClaim) -> StructuralRef:
    if type(table) is not StructuralTable or type(value) is not EquivalentSemanticRouteClaim:
        raise TypeError("route claim capture requires exact table and record")
    return _capture(table, value, set())


def materialize_route_claim(table: StructuralTable, ref: StructuralRef) -> EquivalentSemanticRouteClaim:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("route claim read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (EquivalentSemanticRouteClaim.__module__, EquivalentSemanticRouteClaim.__qualname__):
        raise StructuralIdentityError("handle does not identify a route claim")
    return _materialize(table, ref)


def capture_retirement_catalog(
    table: StructuralTable, value: RetirementCandidateCatalog,
) -> StructuralRef:
    """Detach exact retirement catalog values without granting authority."""
    if type(table) is not StructuralTable or type(value) is not RetirementCandidateCatalog:
        raise TypeError("retirement_catalog capture requires exact table and record")
    return _capture(table, value, set())


def materialize_retirement_catalog(
    table: StructuralTable, ref: StructuralRef,
) -> RetirementCandidateCatalog:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("retirement_catalog read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (RetirementCandidateCatalog.__module__, RetirementCandidateCatalog.__qualname__):
        raise StructuralIdentityError("handle does not identify retirement catalog")
    return _materialize(table, ref)


def capture_entry_allowance(
    table: StructuralTable, value: EntryEndpointLivenessAllowance,
) -> StructuralRef:
    """Detach exact entry allowance values without granting authority."""
    if type(table) is not StructuralTable or type(value) is not EntryEndpointLivenessAllowance:
        raise TypeError("entry_allowance capture requires exact table and record")
    return _capture(table, value, set())


def materialize_entry_allowance(
    table: StructuralTable, ref: StructuralRef,
) -> EntryEndpointLivenessAllowance:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("entry_allowance read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (EntryEndpointLivenessAllowance.__module__, EntryEndpointLivenessAllowance.__qualname__):
        raise StructuralIdentityError("handle does not identify entry allowance")
    return _materialize(table, ref)


def capture_default_gap_forecast(
    table: StructuralTable, value: DefaultGapInfeasibilityForecast,
) -> StructuralRef:
    """Detach the exact default-gap forecast and its base forecast."""
    if type(table) is not StructuralTable or type(value) is not DefaultGapInfeasibilityForecast:
        raise TypeError("default-gap capture requires exact table and forecast")
    return _capture(table, value, set())


def materialize_default_gap_forecast(
    table: StructuralTable, ref: StructuralRef,
) -> DefaultGapInfeasibilityForecast:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("default-gap read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (DefaultGapInfeasibilityForecast.__module__, DefaultGapInfeasibilityForecast.__qualname__):
        raise StructuralIdentityError("handle does not identify a default-gap forecast")
    return _materialize(table, ref)


def capture_corridor_forecast(
    table: StructuralTable, value: CorridorCoverageForecast,
) -> StructuralRef:
    """Detach a base corridor forecast, retaining its supplied derived IDs."""
    if type(table) is not StructuralTable or type(value) is not CorridorCoverageForecast:
        raise TypeError("corridor capture requires exact table and base forecast")
    return _capture(table, value, set())


def materialize_corridor_forecast(
    table: StructuralTable, ref: StructuralRef,
) -> CorridorCoverageForecast:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("corridor read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (CorridorCoverageForecast.__module__, CorridorCoverageForecast.__qualname__):
        raise StructuralIdentityError("handle does not identify a base corridor forecast")
    return _materialize(table, ref)


def capture_plan_inputs(
    table: StructuralTable, value: UnflattenPlanInputCatalog,
) -> StructuralRef:
    """Detach plan inputs without granting plan or handler authority."""
    if type(table) is not StructuralTable or type(value) is not UnflattenPlanInputCatalog:
        raise TypeError("plan input capture requires exact table and catalog")
    return _capture(table, value, set())


def materialize_plan_inputs(
    table: StructuralTable, ref: StructuralRef,
) -> UnflattenPlanInputCatalog:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("plan input read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (UnflattenPlanInputCatalog.__module__, UnflattenPlanInputCatalog.__qualname__):
        raise StructuralIdentityError("handle does not identify plan inputs")
    return _materialize(table, ref)


def capture_use_def_witness(
    table: StructuralTable, value: UseDefFragmentWitness,
) -> StructuralRef:
    """Detach a use-def witness without certifying its proposal or execution."""
    if type(table) is not StructuralTable or type(value) is not UseDefFragmentWitness:
        raise TypeError("use-def capture requires exact table and witness")
    return _capture(table, value, set())


def materialize_use_def_witness(
    table: StructuralTable, ref: StructuralRef,
) -> UseDefFragmentWitness:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("use-def read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (UseDefFragmentWitness.__module__, UseDefFragmentWitness.__qualname__):
        raise StructuralIdentityError("handle does not identify a use-def witness")
    return _materialize(table, ref)


def capture_source_catalog(
    table: StructuralTable, value: SourceIdentityCatalog,
) -> StructuralRef:
    """Copy the exact source family into immutable owner-local terms."""
    if type(table) is not StructuralTable or type(value) is not SourceIdentityCatalog:
        raise TypeError("source catalog capture requires exact table and catalog")
    return _capture(table, value, set())


def _capture(table: StructuralTable, value: object, active: set[int]) -> StructuralRef:
    value_type = type(value)
    if value_type in (type(None), bool, int, str):
        return table.intern(Kind.VALUE, None, (value,), ())
    if value_type in (StorageIdentityKind, UnflattenPlanShape, CorridorPathDisposition, EntryEndpointLivenessReason, TerminalKind, EffectSiteKind, ProviderConsensusMode, SemanticEdgeRole, SemanticSubjectKind, SemanticSubjectRole, UnflattenClaimKind):
        name = object.__getattribute__(value, "_name_")
        encoded_value = object.__getattribute__(value, "_value_")
        if (type(name) is not str or type(encoded_value) is not str
                or value_type.__members__.get(name) is not value):
            raise TypeError("invalid closed storage enum")
        return table.intern(Kind.ENUM, None,
                            (value_type.__module__, value_type.__qualname__, name, encoded_value), ())
    if id(value) in active:
        raise ValueError("source catalog descendant cycle")
    active.add(id(value))
    try:
        if value_type in _SOURCE_FIELDS:
            names = _SOURCE_FIELDS[value_type]
            if tuple(field.name for field in fields(value_type)) != names + _RUNTIME_FIELDS.get(value_type, ()):
                raise TypeError("source catalog descendant schema drift")
            derived = _DERIVED_FIELDS.get(value_type, ())
            children_by_name = {
                name: _capture(table, object.__getattribute__(value, name), active)
                for name in names if name not in derived
            }
            # Close ordinary descendants before invoking a known lazy accessor.
            for name in derived:
                children_by_name[name] = _capture(table, getattr(value, name), active)
            children = tuple(children_by_name[name] for name in names)
            return table.intern(
                Kind.SUBJECT, None,
                (value_type.__module__, value_type.__qualname__), children,
            )
        if value_type is tuple:
            children = tuple(_capture(table, item, active) for item in value)
            return table.intern(Kind.SEQUENCE, None, ("tuple",), children)
        if value_type is frozenset:
            # StableBlockIdentity's only set descendant is exact native EAs.
            if any(type(item) is not int for item in value):
                raise TypeError("source identity EAs require exact integers")
            children = tuple(_capture(table, item, active) for item in sorted(value))
            return table.intern(Kind.SEQUENCE, None, ("frozenset",), children)
        raise TypeError("unsupported source catalog descendant")
    finally:
        active.remove(id(value))


def materialize_source_catalog(
    table: StructuralTable, ref: StructuralRef,
) -> SourceIdentityCatalog:
    """Rebuild an independent public value through the existing constructors."""
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("source catalog read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (SourceIdentityCatalog.__module__, SourceIdentityCatalog.__qualname__):
        raise StructuralIdentityError("handle does not identify a source catalog")
    return _materialize(table, ref)


def _materialize(table: StructuralTable, ref: StructuralRef) -> object:
    node = table.resolve(ref, ref.kind)
    if node.width is not None:
        raise StructuralIdentityError("source term width is outside the schema")
    if ref.kind is Kind.VALUE:
        if (len(node.payload) != 1 or node.children
                or type(node.payload[0]) not in (type(None), bool, int, str)):
            raise StructuralIdentityError("invalid source scalar term")
        return node.payload[0]
    if ref.kind is Kind.ENUM:
        if len(node.payload) != 4 or node.children:
            raise StructuralIdentityError("invalid proposal input enum term")
        enum_type = _SOURCE_ENUMS.get(node.payload[:2])
        name, encoded_value = node.payload[2:]
        if enum_type is None or type(name) is not str or type(encoded_value) is not str:
            raise StructuralIdentityError("unsupported proposal input enum")
        member = enum_type.__members__.get(name)
        if member is None:
            raise StructuralIdentityError("unknown proposal input enum member")
        current_name = object.__getattribute__(member, "_name_")
        current = object.__getattribute__(member, "_value_")
        if (type(current_name) is not str or current_name != name
                or type(current) is not str or current != encoded_value):
            raise StructuralIdentityError("proposal input enum name or value drift")
        return member
    if ref.kind is Kind.SEQUENCE:
        values = tuple(_materialize(table, child) for child in node.children)
        if node.payload == ("tuple",):
            return values
        if node.payload == ("frozenset",) and all(type(item) is int for item in values):
            return frozenset(values)
        raise StructuralIdentityError("invalid source sequence term")
    if ref.kind is not Kind.SUBJECT or node.payload not in _SOURCE_TYPES:
        raise StructuralIdentityError("unsupported source record term")
    record_type = _SOURCE_TYPES[node.payload]
    names = _SOURCE_FIELDS[record_type]
    if len(node.children) != len(names):
        raise StructuralIdentityError("invalid source record field count")
    values = {
        name: _materialize(table, child)
        for name, child in zip(names, node.children)
    }
    supplied_ids = {
        name: values.pop(name) for name in _DERIVED_FIELDS.get(record_type, ())
    }
    result = record_type(**values)
    for name, supplied in supplied_ids.items():
        if type(supplied) is not str or getattr(result, name) != supplied:
            raise StructuralIdentityError("proposal descendant derived identity differs")
    return result
