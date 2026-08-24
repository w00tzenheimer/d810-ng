"""Closed canonical encoding and content IDs for unflatten authority data."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import MISSING, dataclass, fields, is_dataclass
from enum import Enum
import hashlib
import json
import math

from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.transforms.cfg_transaction import TransactionAttemptId

_PREFIX = b"d810-unflatten-authority\0"
SUBJECT_SCHEMA = "unflatten.subject.v1"
CLAIM_SCHEMA = "unflatten.claim.v1"
EVIDENCE_SCHEMA = "unflatten.evidence.v1"
JUSTIFICATION_SCHEMA = "unflatten.justification.v1"
CASE_SCHEMA = "unflatten.case.v1"
RECEIPT_SCHEMA = "unflatten.preparation-receipt.v1"
AUTHORITY_SCHEMA = "unflatten.authority.v1"
BINDING_SCHEMA = "unflatten.binding.v1"
SEMANTIC_GRAPH_SCHEMA = "unflatten.semantic-flowgraph.v1"
SEMANTIC_GRAPH_INVENTORY_SCHEMA = "unflatten.semantic-graph-inventory.v1"
DIGEST_FIXTURE_SCHEMA = "digest-fixture.v1"
_REGISTRIES_READY = False
_ENUM_TYPES: set[type[Enum]] = set()
_RECORD_TYPES: set[type[object]] = set()
_EXTERNAL_TYPES: set[type[object]] = set()
_RECORD_FIELDS: dict[type[object], tuple[str, ...]] = {}
_EXTERNAL_FIELDS: dict[type[object], tuple[str, ...]] = {}
_ENUM_BY_NAME: dict[str, type[Enum]] = {}
_RECORD_BY_NAME: dict[str, type[object]] = {}
_CLAIM_TYPES: set[type[object]] = set()
_EVIDENCE_TYPES: set[type[object]] = set()
_SUBJECT_TYPE: type[object] | None = None
class _DecodedIndexCells:
    __slots__ = ("cells",)

    def __init__(self, cells: tuple[object, ...]) -> None:
        self.cells = cells


@dataclass(frozen=True, slots=True)
class DigestFixture:
    """Fixed conformance record for the canonical wire-format test vector."""

    ea: int
    phase: Enum
    refs: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class MopRecord:
    t: int
    raw_operand_type: int | None
    kind: OperandKind
    size: int
    value: int | None
    stkoff: int | None
    reg: int | None
    block_ref: int | None
    gaddr: int | None
    lvar_off: int | None
    lvar_stkoff: int | None
    switch_cases: tuple[tuple[tuple[int, ...], int], ...]
    stack_refs: tuple[int, ...]
    sub_kind: InsnKind | None
    sub_value_op_kind: ValueOpKind | None
    sub_raw_opcode: int | None
    sub_predicate_kind: PredicateKind | None
    sub_l: MopRecord | None
    sub_r: MopRecord | None
    args: tuple[MopRecord, ...]


@dataclass(frozen=True, slots=True)
class InsnRecord:
    opcode: int
    raw_opcode: int | None
    kind: InsnKind
    ea: int
    native_ea: int | None
    value_op_kind: ValueOpKind | None
    control_transfer_kind: ControlTransferKind | None
    call_kind: CallKind | None
    predicate_kind: PredicateKind | None
    branch_predicate: PredicateKind | None
    compare_width: int | None
    is_conditional_jump: bool
    is_unconditional_jump: bool
    is_call: bool
    l: MopRecord | None  # noqa: E741
    r: MopRecord | None
    d: MopRecord | None
    opcode_attrs: Mapping[str, object]
    display_text_sha256: str


@dataclass(frozen=True, slots=True)
class BlockRecord:
    serial: int
    block_type: int
    raw_block_type: int | None
    kind: BlockKind
    flags: int
    start_ea: int
    native_start_ea: int | None
    succs: tuple[int, ...]
    preds: tuple[int, ...]
    tail_opcode: int | None
    raw_tail_opcode: int | None
    tail_kind: InsnKind | None
    instructions: tuple[InsnRecord, ...]


@dataclass(frozen=True, slots=True)
class GraphRecord:
    func_ea: int
    entry_serial: int
    blocks: tuple[BlockRecord, ...]


_PINNED_RECORD_TYPES = (DigestFixture, MopRecord, InsnRecord, BlockRecord, GraphRecord)


def _validate_id(value: object, label: str = "ID") -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise ValueError(f"{label} must be a sha256 ID")
    if any(char not in "0123456789abcdef" for char in value[7:]):
        raise ValueError(f"{label} must be a sha256 ID")
    return value


def _exact_int(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")


def _exact_bool(value: object, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be an exact bool")


def _optional_int(value: object, label: str) -> None:
    if value is not None:
        _exact_int(value, label)


def _exact_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if type(value) is not enum_type:
        raise TypeError(f"{label} must be {enum_type.__name__}")


def _exact_tuple(value: object, label: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    return value


def _sha256_hex(value: object, label: str) -> None:
    if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be lowercase SHA-256 hex")


def _validate_canonical_value(value: object, seen: set[int] | None = None) -> None:
    """Validate values reachable from pinned records without coercion."""

    seen = set() if seen is None else seen
    if value is None or type(value) in (bool, int, str, bytes):
        return
    if isinstance(value, Enum):
        _ensure_registries()
        if type(value) not in _ENUM_TYPES:
            raise TypeError(f"unregistered enum type: {type(value).__name__}")
        return
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in seen:
            raise ValueError("cyclic canonical mapping")
        seen.add(marker)
        try:
            for key, item in value.items():
                if type(key) is not str:
                    raise TypeError("canonical mappings require string keys")
                _validate_canonical_value(item, seen)
        finally:
            seen.remove(marker)
        return
    if type(value) in (list, tuple, frozenset):
        marker = id(value)
        if marker in seen:
            raise ValueError("cyclic canonical value")
        seen.add(marker)
        for item in value:
            _validate_canonical_value(item, seen)
        seen.remove(marker)
        return
    if type(value) in _PINNED_RECORD_TYPES:
        _validate_pinned_record(value, seen)
        return
    _ensure_registries()
    if type(value) in _RECORD_TYPES or type(value) in _EXTERNAL_TYPES:
        marker = id(value)
        if marker in seen:
            raise ValueError("cyclic registered record")
        seen.add(marker)
        try:
            for name in _RECORD_FIELDS.get(type(value), _EXTERNAL_FIELDS.get(type(value), ())):
                item = type(value).SCHEMA_VERSION if type(value).__name__ == "NativePreanalysisKey" and name == "schema_version" else getattr(value, name)
                if type(value).__name__ in {"PreparationBuildMetrics", "PhaseBuildMetrics"} and name == "inventory_ms":
                    if type(item) not in (int, float) or not math.isfinite(float(item)):
                        raise ValueError("invalid preparation metric")
                elif type(value).__name__ == "GenericEntryGateFacts" and name in {"retained_ratio", "min_retained_ratio"}:
                    if type(item) is not float or not math.isfinite(item):
                        raise ValueError("invalid generic gate ratio")
                else:
                    _validate_canonical_value(item, seen)
        finally:
            seen.remove(marker)
        return
    raise TypeError(f"no canonical encoding for {type(value).__name__}")


def _validate_pinned_record(value: object, seen: set[int] | None = None) -> None:
    """Fail-closed runtime schema validators for the five graph wire records."""

    seen = set() if seen is None else seen
    marker = id(value)
    if marker in seen:
        raise ValueError("cyclic pinned record")
    seen.add(marker)
    try:
        if type(value) is DigestFixture:
            _exact_int(value.ea, "DigestFixture.ea")
            from d810.transforms.unflatten_authority import model
            _exact_enum(value.phase, model.UnflattenAuthorityPhase, "DigestFixture.phase")
            refs = _exact_tuple(value.refs, "DigestFixture.refs")
            for item in refs:
                _validate_canonical_value(item, seen)
            return
        if type(value) is MopRecord:
            _exact_int(value.t, "MopRecord.t")
            _optional_int(value.raw_operand_type, "MopRecord.raw_operand_type")
            _exact_enum(value.kind, OperandKind, "MopRecord.kind")
            _exact_int(value.size, "MopRecord.size")
            for name in ("value", "stkoff", "reg", "block_ref", "gaddr", "lvar_off", "lvar_stkoff", "sub_raw_opcode"):
                _optional_int(getattr(value, name), f"MopRecord.{name}")
            switch_cases = _exact_tuple(value.switch_cases, "MopRecord.switch_cases")
            for case in switch_cases:
                if type(case) is not tuple or len(case) != 2:
                    raise TypeError("MopRecord.switch_cases entries must be pairs")
                case_values = _exact_tuple(case[0], "MopRecord.switch_cases values")
                for item in case_values:
                    _exact_int(item, "MopRecord.switch_cases value")
                _exact_int(case[1], "MopRecord.switch_cases target")
            stack_refs = _exact_tuple(value.stack_refs, "MopRecord.stack_refs")
            for item in stack_refs:
                _exact_int(item, "MopRecord.stack_refs item")
            for name, enum_type in (("sub_kind", InsnKind), ("sub_value_op_kind", ValueOpKind), ("sub_predicate_kind", PredicateKind)):
                item = getattr(value, name)
                if item is not None:
                    _exact_enum(item, enum_type, f"MopRecord.{name}")
            for name in ("sub_l", "sub_r"):
                item = getattr(value, name)
                if item is not None:
                    if type(item) is not MopRecord:
                        raise TypeError(f"MopRecord.{name} must be MopRecord or None")
                    _validate_pinned_record(item, seen)
            args = _exact_tuple(value.args, "MopRecord.args")
            for item in args:
                if type(item) is not MopRecord:
                    raise TypeError("MopRecord.args must contain MopRecord values")
                _validate_pinned_record(item, seen)
            return
        if type(value) is InsnRecord:
            _exact_int(value.opcode, "InsnRecord.opcode")
            _optional_int(value.raw_opcode, "InsnRecord.raw_opcode")
            _exact_enum(value.kind, InsnKind, "InsnRecord.kind")
            _exact_int(value.ea, "InsnRecord.ea")
            _optional_int(value.native_ea, "InsnRecord.native_ea")
            for name, enum_type in (("value_op_kind", ValueOpKind), ("control_transfer_kind", ControlTransferKind), ("call_kind", CallKind), ("predicate_kind", PredicateKind), ("branch_predicate", PredicateKind)):
                item = getattr(value, name)
                if item is not None:
                    _exact_enum(item, enum_type, f"InsnRecord.{name}")
            _optional_int(value.compare_width, "InsnRecord.compare_width")
            for name in ("is_conditional_jump", "is_unconditional_jump", "is_call"):
                _exact_bool(getattr(value, name), f"InsnRecord.{name}")
            for name in ("l", "r", "d"):
                item = getattr(value, name)
                if item is not None:
                    if type(item) is not MopRecord:
                        raise TypeError(f"InsnRecord.{name} must be MopRecord or None")
                    _validate_pinned_record(item, seen)
            if type(value.opcode_attrs) is not dict:
                raise TypeError("InsnRecord.opcode_attrs must be an exact dict")
            _validate_canonical_value(value.opcode_attrs, seen)
            _sha256_hex(value.display_text_sha256, "InsnRecord.display_text_sha256")
            return
        if type(value) is BlockRecord:
            _exact_int(value.serial, "BlockRecord.serial")
            _exact_int(value.block_type, "BlockRecord.block_type")
            _optional_int(value.raw_block_type, "BlockRecord.raw_block_type")
            _exact_enum(value.kind, BlockKind, "BlockRecord.kind")
            _exact_int(value.flags, "BlockRecord.flags")
            _exact_int(value.start_ea, "BlockRecord.start_ea")
            _optional_int(value.native_start_ea, "BlockRecord.native_start_ea")
            for name in ("succs", "preds"):
                items = _exact_tuple(getattr(value, name), f"BlockRecord.{name}")
                for item in items:
                    _exact_int(item, f"BlockRecord.{name} item")
            _optional_int(value.tail_opcode, "BlockRecord.tail_opcode")
            _optional_int(value.raw_tail_opcode, "BlockRecord.raw_tail_opcode")
            if value.tail_kind is not None:
                _exact_enum(value.tail_kind, InsnKind, "BlockRecord.tail_kind")
            instructions = _exact_tuple(value.instructions, "BlockRecord.instructions")
            for item in instructions:
                if type(item) is not InsnRecord:
                    raise TypeError("BlockRecord.instructions must contain InsnRecord values")
                _validate_pinned_record(item, seen)
            return
        if type(value) is GraphRecord:
            _exact_int(value.func_ea, "GraphRecord.func_ea")
            _exact_int(value.entry_serial, "GraphRecord.entry_serial")
            blocks = _exact_tuple(value.blocks, "GraphRecord.blocks")
            serials = []
            by_serial = {}
            for item in blocks:
                if type(item) is not BlockRecord:
                    raise TypeError("GraphRecord.blocks must contain BlockRecord values")
                _validate_pinned_record(item, seen)
                serials.append(item.serial)
                by_serial[item.serial] = item
            if serials != sorted(serials) or len(set(serials)) != len(serials):
                raise ValueError("GraphRecord.blocks must be sorted and unique")
            if blocks and value.entry_serial not in by_serial:
                raise ValueError("GraphRecord.entry_serial must be present")
            for serial, block in by_serial.items():
                if len(set(block.succs)) != len(block.succs) or len(set(block.preds)) != len(block.preds):
                    raise ValueError("GraphRecord topology must not contain duplicate edges")
                for target in (*block.succs, *block.preds):
                    if target not in by_serial:
                        raise ValueError("GraphRecord topology references unknown block")
                for target in block.succs:
                    if serial not in by_serial[target].preds:
                        raise ValueError("GraphRecord topology must be reciprocal")
                for source in block.preds:
                    if serial not in by_serial[source].succs:
                        raise ValueError("GraphRecord topology must be reciprocal")
            return
    finally:
        seen.remove(marker)


def _ensure_registries() -> None:
    global _REGISTRIES_READY
    if _REGISTRIES_READY:
        return
    from d810.analyses.control_flow import semantic_route_evidence as route
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, NativeEaIntervalSet, StableBlockIdentity
    from d810.ir.expressions import ValueOpKind
    from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
    from d810.ir.semantic_edge import SemanticEdgeRole
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.analyses.control_flow.terminal_return_carrier_evidence import (
        TerminalReturnCarrierEvidence,
        TerminalReturnCarrierSource,
        TerminalReturnCarrierSourceKind,
    )
    from d810.analyses.control_flow.materialized_indirect_transfer import TerminalReturnCarrierRequest
    from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef, PlanBlockRef
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority import gates

    _ENUM_TYPES.update({
        model.UnflattenAuthorityPhase, model.SemanticSubjectKind, model.SemanticSubjectRole,
        model.SafetyDimension, model.EvidencePolarity, model.ObligationState,
        model.SubjectBindingStatus, model.SemanticLossKind, model.UnflattenClaimKind, model.ProviderConsensusMode,
        model.StructuralDisposition, model.EffectSiteKind, model.TerminalKind,
        model.CorridorPathDisposition,
        model.GenericCfgGateKind, model.AuthorityEvidenceKind, model.UnflattenJustificationRule,
        model.UnflattenAuthorityReason, model.UnflattenPlanRoute, model.UnflattenPlanShape,
        model.TopologyIncidenceKind,
        model.RetirementProofFamily,
    })
    _ENUM_TYPES.update({
        ValueOpKind, CallKind, ControlTransferKind, PredicateKind, SemanticEdgeRole,
        BlockKind, InsnKind, OperandKind,
        StorageIdentityKind, route.SemanticRouteShape, route.SemanticRouteProofKind,
        route.SemanticPredicateKind, route.SemanticStateWriteDeliveryKind,
        route.CanonicalRouteAssessmentPhase, route.CanonicalRouteAssessmentRejection,
        TerminalReturnCarrierSourceKind,
    })
    model_records = (
        model.BlockSubjectLocator, model.EdgeSubjectLocator, model.RouteSubjectLocator,
        model.EffectSubjectLocator, model.HandlerSubjectLocator, model.TerminalSubjectLocator,
        model.ValueFlowSubjectLocator, model.CorridorSubjectLocator, model.SemanticSubjectRef,
        model.CorridorCoveragePathNode, model.CorridorSemanticExclusion, model.CorridorCoveragePath,
        model.CorridorCoverageForecast, model.CorridorSemanticExclusionCorrelation,
        model.CorridorCoveragePhaseResult,
        model.DetachedDeadHandlerComponentPhaseResult,
        model.DetachedDeadHandlerComponentSourceResult,
        model.DetachedComponentEvidencePayload,
        model.TerminalCyclePhaseResult,
        model.PhaseSubjectBinding, model.PhaseBindingEvidencePayload, model.TopologyEdgeRelation, model.TopologyEvidencePayload,
        model.StructuralLineageEvidencePayload, model.SemanticRouteEvidencePayload,
        model.EffectSiteEvidencePayload, model.ReachabilityEvidencePayload,
        model.UseDefAuditEvidencePayload, model.CorridorCoverageEvidencePayload,
        model.TerminalCycleEvidencePayload,
        model.PatchStepEvidencePayload, model.GenericCfgGateEvidencePayload, model.AuthorityEvidence,
        model.GenericCfgGateResult, model.ProviderConsensusWitness,
        model.RetiredDispatcherInfrastructureClaim, model.DetachedDeadHandlerComponentClaim, model.EquivalentSemanticRouteClaim,
        model.ExactInfeasibleEffectClaim, model.LocalAliasEffectScalarizationClaim,
        model.TerminalCycleBreakClaim, model.UseDefFragmentWitness, model.SourceBlockIdentityWitness,
        model.SourceIdentityCatalog, model.AuthoritativeHandlerInput,
        model.RetirementProofMember, model.RetirementProofContent,
        model.RetirementProofRecord, model.RetirementMemberCatalogRow,
        model.RetirementAuthorityCatalog,
        model.UnflattenPlanInputCatalog, model.ProposedUnflattenContract,
        model.ConditionalSubjectRelation, model.PreparationAuthorityReceipt,
        model.ObligationKey, model.AuthorityJustification, model.ObligationEvidenceCell,
        model.ObligationEvidenceIndex, model.FailedObligation, model.PreparationBuildMetrics,
        model.SemanticLossRow, model.SemanticLossLedger, model.ObservedSemanticLossDelta,
        model.SemanticPhaseMetrics,
        model.PhaseBuildMetrics, model.InventoryInstructionObservation,
        model.InventoryBlockObservation,
        model.InventoryEffectSite, model.InventoryTerminalSite,
        model.InventoryTopologyIncidence, model.SemanticGraphInventory,
        model.DerivedUnflattenPreparationInputs, model.SemanticSafetyCase,
        model.UnflattenAuthorityVerdict,
    )
    _RECORD_TYPES.update({DigestFixture, MopRecord, InsnRecord, BlockRecord, GraphRecord, *model_records})
    _CLAIM_TYPES.update({
        model.RetiredDispatcherInfrastructureClaim,
        model.DetachedDeadHandlerComponentClaim,
        model.EquivalentSemanticRouteClaim,
        model.ExactInfeasibleEffectClaim,
        model.LocalAliasEffectScalarizationClaim,
        model.TerminalCycleBreakClaim,
    })
    _EVIDENCE_TYPES.add(model.AuthorityEvidence)
    global _SUBJECT_TYPE
    _SUBJECT_TYPE = model.SemanticSubjectRef
    _RECORD_FIELDS.update({
        DigestFixture: ("ea", "phase", "refs"),
        MopRecord: ("t", "raw_operand_type", "kind", "size", "value", "stkoff", "reg", "block_ref", "gaddr", "lvar_off", "lvar_stkoff", "switch_cases", "stack_refs", "sub_kind", "sub_value_op_kind", "sub_raw_opcode", "sub_predicate_kind", "sub_l", "sub_r", "args"),
        InsnRecord: ("opcode", "raw_opcode", "kind", "ea", "native_ea", "value_op_kind", "control_transfer_kind", "call_kind", "predicate_kind", "branch_predicate", "compare_width", "is_conditional_jump", "is_unconditional_jump", "is_call", "l", "r", "d", "opcode_attrs", "display_text_sha256"),
        BlockRecord: ("serial", "block_type", "raw_block_type", "kind", "flags", "start_ea", "native_start_ea", "succs", "preds", "tail_opcode", "raw_tail_opcode", "tail_kind", "instructions"),
        GraphRecord: ("func_ea", "entry_serial", "blocks"),
        model.BlockSubjectLocator: ("block_ref", "anchor_ea"),
        model.EdgeSubjectLocator: ("source_ref", "source_anchor_ea", "target_ref", "target_anchor_ea", "edge_role"),
        model.RouteSubjectLocator: ("proof_id", "atomic_group_id", "source_ref", "source_anchor_ea", "destination_refs", "destination_anchor_eas"),
        model.EffectSubjectLocator: ("owner_ref", "owner_anchor_ea", "instruction_ea", "effect_kind"),
        model.HandlerSubjectLocator: ("block_ref", "anchor_ea", "normalized_states"),
        model.TerminalSubjectLocator: ("block_ref", "anchor_ea", "terminal_kind", "instruction_ea"),
        model.ValueFlowSubjectLocator: ("fragment_id", "state_identity", "redirect_owner_refs"),
        model.CorridorSubjectLocator: ("corridor_id", "entry_ref", "entry_anchor_ea", "member_refs", "member_anchor_eas"),
        model.CorridorCoveragePathNode: ("block_ref", "anchor_ea"),
        model.CorridorSemanticExclusion: ("exclusion_id", "digest", "normalized_state", "state_identity", "source", "feeder", "prefix", "root"),
        model.CorridorCoveragePath: ("path_id", "nodes", "state_merge", "disposition", "semantic_exclusion_ids"),
        model.CorridorCoverageForecast: ("forecast_id", "plan_id", "function_ea", "source_native_key", "source_generation", "dispatcher_ref", "dispatcher_anchor_ea", "paths", "covered_path_ids", "residual_path_ids", "enumeration_complete", "semantic_exclusion_digests", "semantic_exclusions", "semantic_exclusion_path_ids"),
            model.CorridorSemanticExclusionCorrelation: ("exclusion_id", "exclusion_digest", "path_id", "claim_id", "proof_id", "ordered_prefix", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "phase_result_id"),
            model.CorridorCoveragePhaseResult: ("result_id", "forecast_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "covered_path_ids", "residual_path_ids", "drifted_path_ids", "enumeration_complete", "matched_semantic_exclusion_ids", "source_dispatcher_reachable", "candidate_dispatcher_reachable", "semantic_exclusion_correlations", "comparison_region_subject_ids", "dispatcher_subject_id"),
            model.DetachedDeadHandlerComponentSourceResult: ("result_id", "claim_id", "corridor_forecast_id", "corridor_coverage_result_id", "source_fingerprint", "source_generation", "dispatcher_subject_id", "dispatcher_block_ref", "dead_handler_subject_ids", "retained_handler_subject_ids", "component_subject_ids", "comparison_region_subject_ids", "source_reachable_subject_ids", "dead_handler_block_refs", "retained_handler_block_refs", "comparison_region_block_refs", "terminal_digest", "effect_digest", "topology_digest", "source_reachable_block_refs", "component_block_refs", "remainder_block_refs", "terminal_site_keys", "effect_site_keys", "source_blocks"),
            model.DetachedDeadHandlerComponentPhaseResult: ("result_id", "claim_id", "phase", "corridor_coverage_result_id", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "accepted", "source_result_id"),
            model.DetachedComponentEvidencePayload: ("phase_result_id", "claim_id", "corridor_coverage_result_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "accepted", "authorized_subject_ids"),
            model.TerminalCyclePhaseResult: ("result_id", "claim_id", "terminal_route_proof_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "bound_subject_ids", "source_binding_digest", "candidate_binding_digest", "residue_refs", "source_cycle_edges", "candidate_cycle_edges", "source_bindings", "candidate_bindings", "terminal_source_ref", "cleanup_source_ref", "terminal_carrier_ref", "terminal_route_refs", "terminal_subject_id", "terminal_subject_ref"),
        model.SemanticSubjectRef: ("kind", "role", "subject_id", "block_ref", "anchor_ea", "locator"),
        model.PhaseSubjectBinding: ("subject", "phase", "block_ref", "graph_fingerprint", "generation", "status", "serial", "anchor_ea", "native_instruction_eas", "role"),
        model.PhaseBindingEvidencePayload: ("binding",),
        model.TopologyEdgeRelation: ("role", "source_subject_id", "target_subject_id", "native_edge_anchor_ea"),
        model.TopologyEvidencePayload: ("subject_id", "predecessor_subject_ids", "successor_subject_ids", "reciprocal_edges", "expected_shape_digest", "candidate_shape_digest", "expected_edge_relations", "candidate_edge_relations"),
        model.StructuralLineageEvidencePayload: ("source_subject_id", "candidate_subject_ids", "disposition", "reciprocal_native_origin_eas", "claim_id", "source_subject_ids"),
        model.SemanticRouteEvidencePayload: ("route_subject_id", "proof_ids", "atomic_group_id", "source_subject_id", "destination_subject_ids", "matched"),
        model.EffectSiteEvidencePayload: ("effect_subject_id", "effect_kind", "instruction_ea", "opcode", "width", "storage_identity", "normalized_state", "provider_mode", "provider_ids", "preserved"),
        model.ReachabilityEvidencePayload: ("root_subject_id", "target_subject_id", "reachable", "path_subject_ids"),
        model.UseDefAuditEvidencePayload: ("fragment_id", "state_identity", "executed", "fragment_atomic", "actionable_non_state_severance_count", "violation_ids"),
        model.CorridorCoverageEvidencePayload: ("corridor_subject_id", "forecast_id", "phase_result_id", "covered_path_ids", "residual_path_ids", "drifted_path_ids", "enumeration_complete", "matched_semantic_exclusion_ids", "source_dispatcher_reachable", "candidate_dispatcher_reachable"),
        model.TerminalCycleEvidencePayload: ("phase_result_id", "claim_id", "terminal_route_proof_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "bound_subject_ids", "source_binding_digest", "candidate_binding_digest", "residue_refs", "source_cycle_edges", "candidate_cycle_edges", "source_bindings", "candidate_bindings", "terminal_source_ref", "cleanup_source_ref", "terminal_carrier_ref", "terminal_route_refs", "terminal_subject_id", "terminal_subject_ref"),
        model.PatchStepEvidencePayload: ("plan_id", "step_index", "step_type", "owner_ref", "step_digest", "host_ea", "host_opcode", "value_size"),
        model.GenericCfgGateEvidencePayload: ("gate", "passed", "affected_subject_ids", "reason_code"),
        model.AuthorityEvidence: ("evidence_id", "kind", "subject", "phase", "payload"),
        model.GenericCfgGateResult: ("gate", "passed", "supported_subject_ids", "refuted_subject_ids", "reason_code"),
        model.ProviderConsensusWitness: ("mode", "provider_ids"),
        model.RetiredDispatcherInfrastructureClaim: ("claim_id", "kind", "infrastructure_subject", "corridor_subject", "member_subjects", "retirement_proof_ids", "source_generation", "retirement_catalog"),
        model.DetachedDeadHandlerComponentClaim: ("claim_id", "kind", "dispatcher_subject", "dead_handler_subjects", "retained_handler_subjects", "component_subjects", "source_generation"),
        model.EquivalentSemanticRouteClaim: ("claim_id", "kind", "retired_route_subject", "replacement_route_subject", "source_subject", "destination_subjects", "route_proof_ids", "atomic_group_id", "source_generation"),
        model.ExactInfeasibleEffectClaim: ("claim_id", "kind", "effect_subject", "source_subject", "predicate_subject", "selected_target_subject", "discarded_effect_subject", "normalized_state", "state_identity", "width", "source_write_ea", "predicate_branch_ea", "discarded_effect_ea", "selected_edge_role", "route_proof_ids", "consensus", "source_generation"),
        model.LocalAliasEffectScalarizationClaim: ("claim_id", "kind", "owner_subject", "step_index", "host_ea", "host_opcode", "alias_token", "base_token", "host_text_sha1", "value_size", "step_digest", "source_generation"),
        model.TerminalCycleBreakClaim: ("claim_id", "kind", "cycle_subject", "cleanup_source_subject", "terminal_subject", "terminal_route_proof_ids", "source_generation"),
        model.UseDefFragmentWitness: ("fragment_id", "state_identity", "redirect_owner_refs", "redirect_digest", "executed", "fragment_atomic", "actionable_non_state_severance_count", "violation_ids"),
        model.SourceBlockIdentityWitness: ("block_ref", "anchor_ea", "native_instruction_eas"),
        model.SourceIdentityCatalog: ("native_key", "generation", "blocks"),
        model.RetirementProofMember: ("block_ref", "anchor_ea", "retired", "role"),
        model.RetirementProofContent: ("family", "source_generation", "members"),
        model.RetirementProofRecord: ("proof_id", "content"),
        model.RetirementMemberCatalogRow: ("block_ref", "anchor_ea", "native_instruction_eas", "source_generation", "retired", "proofs"),
        model.RetirementAuthorityCatalog: ("catalog_id", "source_generation", "members", "proofs"),
        model.AuthoritativeHandlerInput: ("block_ref", "anchor_ea", "normalized_states"),
        model.UnflattenPlanInputCatalog: ("shape", "source_entry_ref", "dispatcher_entry_ref", "dispatcher_member_refs", "authoritative_handlers", "state_identity"),
        model.ProposedUnflattenContract: ("schema_version", "rule_set_version", "plan_id", "route_evidence", "source_identity_catalog", "use_def_witness", "claims", "plan_inputs", "retirement_catalog", "corridor_coverage_forecast"),
        model.ObligationKey: ("subject", "dimension"),
        model.AuthorityJustification: ("justification_id", "rule", "premise_ids", "conclusion", "polarity", "phase", "claim_id"),
        model.ObligationEvidenceCell: ("key", "phase", "supporting_justification_ids", "refuting_justification_ids"),
        model.ObligationEvidenceIndex: ("cells",),
        model.FailedObligation: ("key", "state"),
        model.SemanticLossRow: ("case", "source_subject", "source_binding", "candidate_binding", "structural_obligation", "relevant_semantic_obligations", "justifications", "evidence", "claims"),
        model.SemanticLossLedger: ("case", "authority_id", "case_id", "phase", "source_fingerprint", "candidate_fingerprint", "rows"),
        model.ObservedSemanticLossDelta: ("authority_id", "source_fingerprint", "projected_case_id", "observed_case_id", "rows"),
        model.PreparationBuildMetrics: ("source_inventory_builds", "candidate_inventory_builds", "inventory_ms"),
            model.SemanticPhaseMetrics: ("preparation_metrics", "source_inventory_builds", "candidate_inventory_builds", "index_folds", "view_graph_traversals", "phase", "phase_build_metrics"),
        model.PhaseBuildMetrics: ("phase", "source_inventory_builds", "candidate_inventory_builds", "inventory_ms"),
        model.InventoryInstructionObservation: ("ordinal", "instruction_ea", "opcode", "width", "instruction_kind", "control_transfer_kind", "is_call", "call_kind", "display_text"),
        model.InventoryBlockObservation: ("serial", "block_ref", "anchor_ea", "native_instruction_eas", "predecessor_serials", "successor_serials", "transfer_ea", "instruction_observations", "block_kind", "graph_start_ea"),
        model.InventoryEffectSite: ("owner_serial", "owner_ref", "owner_anchor_ea", "instruction_ordinal", "instruction_ea", "effect_kind", "opcode", "width"),
        model.InventoryTerminalSite: ("owner_serial", "owner_ref", "owner_anchor_ea", "instruction_ordinal", "instruction_ea", "terminal_kind"),
        model.InventoryTopologyIncidence: ("kind", "owner_serial", "peer_serial", "source_transfer_ea"),
        model.SemanticGraphInventory: ("phase", "graph_fingerprint", "generation", "blocks", "subjects", "bindings", "effects", "terminals", "topology", "inventory_digest", "reachable_serials", "entry_serial", "source_subject_ids", "function_ea"),
        model.ConditionalSubjectRelation: ("source_subject_id", "target_subject_id", "dimension", "provenance_id"),
                model.PreparationAuthorityReceipt: ("receipt_id", "proposal_id", "plan_id", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "source_inventory_digest", "candidate_inventory_digest", "source_binding_digest", "candidate_binding_digest", "route_expansion_digest", "effect_catalog_digest", "terminal_catalog_digest", "plan_input_digest", "dispatcher_member_digest", "planned_helper_digest", "patch_step_digest", "conditional_relation_digest", "projected_topology_reference_digest", "metrics", "generic_gate_facts_digest", "route_assessment_digest", "retirement_catalog", "corridor_coverage_forecast"),
        model.DerivedUnflattenPreparationInputs: ("proposal", "claims", "preparation_receipt", "source_inventory", "candidate_inventory", "projected_topology_reference", "source_route_assessment", "candidate_route_assessment", "generic_gate_facts", "conditional_relations", "patch_step_facts", "preparation_metrics", "phase_build_metrics", "corridor_coverage_phase_result", "detached_dead_handler_component_source_results", "detached_dead_handler_component_phase_results", "terminal_cycle_phase_results"),
        model.SemanticSafetyCase: ("case_id", "authority_id", "preparation_receipt_id", "preparation_receipt", "phase", "source_fingerprint", "candidate_fingerprint", "candidate_generation", "claims", "subjects", "bindings", "conditional_relations", "required_obligations", "evidence", "justifications", "obligation_index", "phase_metrics", "source_inventory", "candidate_inventory", "source_subject_ids", "source_bindings", "retirement_catalog", "corridor_coverage_phase_result", "detached_dead_handler_component_source_results", "detached_dead_handler_component_phase_results", "terminal_cycle_phase_results"),
        model.UnflattenAuthorityVerdict: ("accepted", "phase", "reason", "authority_id", "binding_id", "case_id", "candidate_fingerprint", "safety_case", "failed_obligations"),
    })
    _EXTERNAL_TYPES.update({
        NativePreanalysisKey, NativeEaInterval, NativeEaIntervalSet, StorageIdentity,
        StableBlockIdentity, LogicalBlockRef, NativeBlockRef, PlanBlockRef,
        TransactionAttemptId,
            route.SemanticCorridorPoint, route.SemanticPredicateProof, route.SemanticCarrierProof,
            route.SemanticRouteDestination, route.SemanticStateWriteProof, route.SemanticRouteProof,
            route.CanonicalSemanticEvidence,
            route.BoundSemanticBlock, route.BoundSemanticRouteDestination,
            route.BoundSemanticPredicate, route.BoundSemanticCarrier,
            route.BoundSemanticRoute, route.BoundCanonicalSemanticEvidence,
        TerminalReturnCarrierEvidence,
        gates.GenericEntryGateFacts, gates.GenericEffectfulGateFacts,
        gates.GenericTerminalGateFacts, gates.GenericCfgGateFacts,
        TerminalReturnCarrierSource, TerminalReturnCarrierRequest,
    })
    _EXTERNAL_FIELDS.update({
        NativePreanalysisKey: ("schema_version", "input_identity", "processor", "bitness", "function_rva", "function_fingerprint", "profile_fingerprint", "sdk_fingerprint"),
        TransactionAttemptId: ("plan_id", "session_id", "generation", "attempt_id"),
        NativeEaInterval: ("start_ea", "end_ea"),
        NativeEaIntervalSet: ("intervals",),
        StorageIdentity: ("kind", "offset"),
        StableBlockIdentity: ("native_key", "exact_instruction_eas", "native_ranges"),
        LogicalBlockRef: ("session_id", "proxy_token", "version"),
        NativeBlockRef: ("identity",),
        PlanBlockRef: ("plan_id", "local_block_id"),
        route.SemanticCorridorPoint: ("identity", "anchor_ea"),
        route.SemanticPredicateProof: ("kind", "origin", "consumer", "corridor", "storage_identity", "width", "compare_constant", "true_is_taken", "permitted_write_eas"),
        route.SemanticCarrierProof: ("carrier_id", "definition", "consumers", "corridor", "storage_identity", "width", "state_values", "permitted_write_eas"),
        route.SemanticRouteDestination: ("role", "state_constant", "target_identity", "target_anchor_ea", "terminal"),
        route.SemanticStateWriteProof: ("identity", "instruction_ea", "state_variable", "width", "state_constant", "corridor_instruction_eas", "authority_transfer_ea", "preserved_call_instruction_eas", "delivery_kind"),
        route.SemanticRouteProof: ("proof_id", "atomic_group_id", "proof_kind", "shape", "source_identity", "source_anchor_ea", "destinations", "delivery_region", "source_owner_identity", "source_owner_anchor_ea", "state_write", "predicate", "carriers", "terminal_return_carrier", "diagnostic_provenance"),
            route.CanonicalSemanticEvidence: ("native_key", "generation", "atomic_group_id", "route_proofs"),
            route.BoundSemanticBlock: ("serial", "identity", "anchor_ea"),
            route.BoundSemanticRouteDestination: ("evidence", "block"),
            route.BoundSemanticPredicate: ("evidence", "origin", "consumer", "corridor"),
            route.BoundSemanticCarrier: ("evidence", "definition", "consumers", "corridor"),
            route.BoundSemanticRoute: ("evidence", "source", "destinations", "source_owner", "state_write_block", "predicate", "carriers"),
            route.BoundCanonicalSemanticEvidence: ("evidence", "routes"),
        gates.GenericEntryGateFacts: ("passed", "pre_reachable_count", "post_reachable_count", "retained_ratio", "min_pre_reachable", "min_retained_ratio", "reason"),
        gates.GenericEffectfulGateFacts: ("passed", "pre_effectful_block_serials", "post_reachable_effectful_block_serials", "lost_block_serials", "reason"),
        gates.GenericTerminalGateFacts: ("passed", "pre_reachable_terminals", "post_reachable_terminals", "pre_reachable_count", "post_reachable_count", "reason"),
        gates.GenericCfgGateFacts: ("entry", "effectful_raw", "effectful_effective", "terminal"),
        TerminalReturnCarrierEvidence: ("request", "capture_identity", "terminal_identity", "state_write_ea", "carrier_ea", "terminal_return_ea", "operation", "source", "return_width", "corridor_instruction_eas"),
        TerminalReturnCarrierSource: ("kind", "width", "storage_identity", "constant"),
        TerminalReturnCarrierRequest: ("source_handler_ea", "terminal_target_ea", "state_var_reg", "state_constant"),
    })
    for enum_type in _ENUM_TYPES:
        if enum_type.__name__ in _ENUM_BY_NAME and _ENUM_BY_NAME[enum_type.__name__] is not enum_type:
            raise RuntimeError(f"duplicate canonical enum name: {enum_type.__name__}")
        _ENUM_BY_NAME[enum_type.__name__] = enum_type
    for record_type in (*_RECORD_TYPES, *_EXTERNAL_TYPES):
        if record_type.__name__ in _RECORD_BY_NAME and _RECORD_BY_NAME[record_type.__name__] is not record_type:
            raise RuntimeError(f"duplicate canonical record name: {record_type.__name__}")
        _RECORD_BY_NAME[record_type.__name__] = record_type
    for record_type, names in _RECORD_FIELDS.items():
        declared = tuple(field.name for field in fields(record_type) if not field.name.startswith("_"))
        if names != declared:
            raise RuntimeError(f"canonical record schema drift: {record_type.__name__}")
    for external_type, names in _EXTERNAL_FIELDS.items():
        declared = tuple(field.name for field in fields(external_type) if not field.name.startswith("_"))
        if external_type is NativePreanalysisKey:
            expected = ("schema_version",) + declared
        else:
            expected = declared
        if names != expected:
            raise RuntimeError(f"canonical external schema drift: {external_type.__name__}")
    _REGISTRIES_READY = True


def _wire(value: object) -> object:
    _ensure_registries()
    if value is None:
        return {"t": "none"}
    if type(value) is bool:
        return {"t": "bool", "v": value}
    if type(value) is int:
        return {"t": "int", "v": str(value)}
    if type(value) is str:
        return {"t": "str", "v": value}
    if type(value) is bytes:
        return {"t": "bytes", "v": value.hex()}
    if isinstance(value, Enum):
        if type(value) not in _ENUM_TYPES:
            raise TypeError(f"unregistered enum type: {type(value).__name__}")
        return {"t": "enum", "n": type(value).__name__, "v": _wire(value.value)}
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise TypeError("canonical mappings require string keys")
        pairs = [(_wire(key), _wire(item)) for key, item in value.items()]
        pairs.sort(key=lambda pair: _json_bytes(pair[0]))
        return {"t": "map", "v": [[key, item] for key, item in pairs]}
    if type(value) is list:
        return {"t": "list", "v": [_wire(item) for item in value]}
    if type(value) is tuple:
        return {"t": "tuple", "v": [_wire(item) for item in value]}
    if type(value) is frozenset:
        items = [_wire(item) for item in value]
        items.sort(key=_json_bytes)
        return {"t": "frozenset", "v": items}
    if type(value) in _PINNED_RECORD_TYPES:
        _validate_pinned_record(value)
    if type(value) in _EXTERNAL_TYPES:
        return _external_wire(value)
    if type(value) in _RECORD_TYPES and is_dataclass(value):
        names = _RECORD_FIELDS[type(value)]
        pairs = []
        for name in names:
            field_value = getattr(value, name)
            if type(value).__name__ in {"PreparationBuildMetrics", "PhaseBuildMetrics"} and name == "inventory_ms":
                if type(field_value) not in (int, float) or not math.isfinite(float(field_value)):
                    raise ValueError("invalid preparation metric")
                encoded = {"t": "decimal", "v": float(field_value).hex()}
            else:
                encoded = _wire(field_value)
            pairs.append([name, encoded])
        return {"t": "record", "n": type(value).__name__, "v": pairs}
    raise TypeError(f"no canonical encoding for {type(value).__name__}")


def _external_wire(value: object) -> object:
    names = _EXTERNAL_FIELDS.get(type(value))
    if names is None:
        raise TypeError(f"unregistered external type: {type(value).__name__}")
    pairs = []
    for name in names:
        item = type(value).SCHEMA_VERSION if type(value).__name__ == "NativePreanalysisKey" and name == "schema_version" else getattr(value, name)
        if type(value).__name__ == "GenericEntryGateFacts" and name in {"retained_ratio", "min_retained_ratio"}:
            if type(item) is not float or not math.isfinite(item):
                raise ValueError("invalid generic gate ratio")
            encoded = {"t": "decimal", "v": item.hex()}
        else:
            encoded = _wire(item)
        pairs.append([name, encoded])
    return {"t": "record", "n": type(value).__name__, "v": pairs}


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def canonical_bytes(value: object) -> bytes:
    _validate_canonical_value(value)
    return _json_bytes(_wire(value))


def _decode_wire(value: object, *, allow_index: bool = False) -> object:
    _ensure_registries()
    if not isinstance(value, dict) or not isinstance(value.get("t"), str):
        raise ValueError("invalid canonical wire value")
    tag = value["t"]
    expected = {
        "none": {"t"}, "bool": {"t", "v"}, "int": {"t", "v"},
        "str": {"t", "v"}, "decimal": {"t", "v"}, "bytes": {"t", "v"}, "list": {"t", "v"},
        "tuple": {"t", "v"}, "frozenset": {"t", "v"}, "map": {"t", "v"},
        "enum": {"t", "n", "v"}, "record": {"t", "n", "v"},
    }.get(tag)
    if expected is None or set(value) != expected:
        raise ValueError("invalid canonical wire tag shape")
    if tag == "none":
        result: object = None
    elif tag == "bool":
        if type(value["v"]) is not bool:
            raise ValueError("invalid bool wire value")
        result = value["v"]
    elif tag == "int":
        if type(value["v"]) is not str or not value["v"] or (value["v"] != "0" and value["v"].startswith("0")):
            raise ValueError("invalid int wire value")
        try:
            result = int(value["v"])
        except ValueError as exc:
            raise ValueError("invalid int wire value") from exc
    elif tag == "str":
        if type(value["v"]) is not str:
            raise ValueError("invalid str wire value")
        result = value["v"]
    elif tag == "decimal":
        if type(value["v"]) is not str:
            raise ValueError("invalid decimal wire value")
        try:
            result = float.fromhex(value["v"])
        except ValueError as exc:
            raise ValueError("invalid decimal wire value") from exc
        if not math.isfinite(result):
            raise ValueError("invalid decimal wire value")
    elif tag == "bytes":
        if type(value["v"]) is not str:
            raise ValueError("invalid bytes wire value")
        try:
            result = bytes.fromhex(value["v"])
        except ValueError as exc:
            raise ValueError("invalid bytes wire value") from exc
    elif tag == "list":
        if type(value["v"]) is not list:
            raise ValueError("invalid list wire value")
        result = [_decode_wire(item, allow_index=allow_index) for item in value["v"]]
    elif tag == "tuple":
        if type(value["v"]) is not list:
            raise ValueError("invalid tuple wire value")
        result = tuple(_decode_wire(item, allow_index=allow_index) for item in value["v"])
    elif tag == "frozenset":
        if type(value["v"]) is not list:
            raise ValueError("invalid frozenset wire value")
        result = frozenset(_decode_wire(item, allow_index=allow_index) for item in value["v"])
    elif tag == "map":
        if type(value["v"]) is not list:
            raise ValueError("invalid map wire value")
        result = {}
        for encoded_key, item in value["v"]:
            if type(encoded_key) is not dict or type(item) is not dict:
                raise ValueError("invalid map pair")
            key = _decode_wire(encoded_key, allow_index=allow_index)
            if type(key) is not str:
                raise ValueError("canonical mapping key must decode to string")
            if key in result:
                raise ValueError("duplicate canonical mapping key")
            result[key] = _decode_wire(item, allow_index=allow_index)
    elif tag == "enum":
        if type(value["n"]) is not str:
            raise ValueError("invalid enum name")
        enum_type = _ENUM_BY_NAME.get(value["n"])
        if enum_type is None:
            raise ValueError("unknown enum name")
        raw = _decode_wire(value["v"], allow_index=allow_index)
        try:
            result = enum_type(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("unknown enum value") from exc
    else:
        if type(value["n"]) is not str or type(value["v"]) is not list:
            raise ValueError("invalid record wire value")
        record_type = _RECORD_BY_NAME.get(value["n"])
        if record_type is None:
            raise ValueError("unknown record name")
        names = _RECORD_FIELDS.get(record_type, _EXTERNAL_FIELDS.get(record_type))
        if names is None or len(value["v"]) != len(names):
            raise ValueError("invalid record fields")
        seen: set[str] = set()
        kwargs: dict[str, object] = {}
        for pair, expected_name in zip(value["v"], names):
            if type(pair) is not list or len(pair) != 2 or type(pair[0]) is not str:
                raise ValueError("invalid record field")
            name = pair[0]
            if name in seen or name != expected_name:
                raise ValueError("invalid record field order")
            seen.add(name)
            kwargs[name] = _decode_wire(
                pair[1],
                allow_index=(allow_index or (
                    record_type.__name__ == "SemanticSafetyCase"
                    and name == "obligation_index"
                )),
            )
        try:
            if record_type.__name__ == "NativePreanalysisKey":
                result = record_type.from_dict(kwargs)
            elif record_type.__name__ == "ObligationEvidenceIndex":
                if not allow_index:
                    raise ValueError("obligation indexes require case context")
                # Keep untrusted serialized cells unprivileged until the
                # surrounding case has recomputed and compared its fold.
                result = _DecodedIndexCells(kwargs["cells"])
            elif record_type.__name__ == "PreparationAuthorityReceipt":
                # Receipts are constructor-closed transaction records, but
                # canonical replay must still reconstruct and revalidate
                # the exact sealed value carried by a safety case.
                result = record_type.__new__(record_type)
                for name, item in kwargs.items():
                    object.__setattr__(result, name, item)
                object.__setattr__(result, "_minted", True)
                record_type.__post_init__(result)
            elif record_type.__name__ == "SemanticSafetyCase":
                serialized_index = kwargs.get("obligation_index")
                if not isinstance(serialized_index, _DecodedIndexCells):
                    raise ValueError("case obligation index lacks decode context")
                from d810.transforms.unflatten_authority.evaluate import (
                    _build_obligation_index,
                    _validate_justification_graph,
                )
                _validate_justification_graph(
                    kwargs["justifications"], kwargs["required_obligations"],
                    kwargs["evidence"], kwargs["phase"], kwargs["claims"],
                    kwargs["conditional_relations"],
                    candidate_fingerprint=kwargs["candidate_fingerprint"],
                    candidate_generation=kwargs["candidate_generation"],
                    bindings=kwargs["bindings"],
                    subjects=kwargs["subjects"],
                    source_subject_ids=kwargs["source_subject_ids"],
                )
                expected_index = _build_obligation_index(
                    kwargs["required_obligations"], kwargs["justifications"], kwargs["phase"],
                )
                if serialized_index.cells != expected_index.cells:
                    raise ValueError("serialized obligation index does not match the case fold")
                kwargs["obligation_index"] = expected_index
                result = record_type(**kwargs)
            else:
                result = record_type(**kwargs)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid record value") from exc
        if type(result) in _PINNED_RECORD_TYPES:
            _validate_pinned_record(result)
    if isinstance(result, _DecodedIndexCells):
        return result
    if tag == "decimal":
        canonical_value = {"t": "decimal", "v": result.hex()}
    else:
        canonical_value = _wire(result)
    if canonical_value != value:
        raise ValueError("non-canonical wire encoding")
    return result


def canonical_decode(encoded: bytes) -> object:
    if not isinstance(encoded, bytes):
        raise TypeError("canonical encoding must be bytes")
    try:
        value = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid canonical encoding") from exc
    result = _decode_wire(value)
    if type(result).__name__ == "ObligationEvidenceIndex":
        raise ValueError("obligation indexes are evaluator-owned and require case context")
    if canonical_bytes(result) != encoded:
        raise ValueError("non-canonical canonical encoding")
    return result


def validate_canonical_roundtrip(value: object, expected_type: type[object]) -> object:
    """Require the exact persistence decode and canonical representation."""

    encoded = canonical_bytes(value)
    decoded = canonical_decode(encoded)
    if type(decoded) is not expected_type or decoded != value:
        raise ValueError("canonical roundtrip changed the authority value")
    if canonical_bytes(decoded) != encoded:
        raise ValueError("canonical roundtrip is not stable")
    return decoded


def content_id(schema: str, value: object) -> str:
    if not isinstance(schema, str) or not schema.isascii() or not schema.strip():
        raise ValueError("schema must be non-empty ASCII")
    preimage = _PREFIX + schema.encode("ascii") + b"\0" + canonical_bytes(value)
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def subject_id(kind: Enum, role: Enum, locator: object) -> str:
    """Compute the subject ID from exactly kind, role, and locator."""

    return content_id(SUBJECT_SCHEMA, (kind, role, locator))


def claim_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _CLAIM_TYPES:
        raise TypeError("claim_id requires a registered claim record")
    return _record_content_id(CLAIM_SCHEMA, value, "claim_id")


def evidence_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _EVIDENCE_TYPES:
        raise TypeError("evidence_id requires a registered evidence record")
    return _record_content_id(EVIDENCE_SCHEMA, value, "evidence_id")


def justification_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _RECORD_TYPES:
        raise TypeError("justification_id requires a registered justification record")
    return _record_content_id(JUSTIFICATION_SCHEMA, value, "justification_id")


def case_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _RECORD_TYPES:
        raise TypeError("case_id requires a registered safety case record")
    return _record_content_id(CASE_SCHEMA, value, "case_id")


def receipt_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _RECORD_TYPES:
        raise TypeError("receipt_id requires a registered preparation receipt")
    return _record_content_id(RECEIPT_SCHEMA, value, "receipt_id")


def authority_id(value: object) -> str:
    return content_id(AUTHORITY_SCHEMA, value)


def binding_id(value: object) -> str:
    return content_id(BINDING_SCHEMA, value)


def semantic_graph_inventory_digest(*fields: object) -> str:
    """Digest the complete inventory payload, excluding its digest field."""
    if len(fields) != 13:
        raise TypeError("semantic graph inventory digest requires thirteen fields")
    return content_id(SEMANTIC_GRAPH_INVENTORY_SCHEMA, tuple(fields))


def bound_unflatten_binding_id(prepared: object, patch_binding: object) -> str:
    """Compute the one canonical ID for a prepared live bound plan."""
    return binding_id((
        prepared.authority_id,
        patch_binding.bindings,
        patch_binding.attempt_id,
        patch_binding.maturity.dumps(),
        patch_binding.session_id,
        patch_binding.generation,
    ))


def _subject_id_from_record(value: object) -> str:
    _ensure_registries()
    if type(value) is not _SUBJECT_TYPE:
        raise TypeError("subject ID requires SemanticSubjectRef")
    return subject_id(value.kind, value.role, value.locator)


def _subject_factory(cls: type[object], **kwargs: object) -> object:
    _ensure_registries()
    if cls is not _SUBJECT_TYPE:
        raise TypeError("subject factory requires SemanticSubjectRef")
    required = {"kind", "role", "block_ref", "anchor_ea", "locator"}
    if set(kwargs) != required:
        raise TypeError("subject factory requires exactly the subject fields")
    kwargs["subject_id"] = subject_id(kwargs["kind"], kwargs["role"], kwargs["locator"])
    return cls(**kwargs)


def _record_content_id(schema: str, value: object, omitted_field: str) -> str:
    if not is_dataclass(value) or isinstance(value, type):
        raise TypeError("content ID factory requires a registered record")
    _ensure_registries()
    if type(value) not in _RECORD_TYPES:
        raise TypeError(f"unregistered record type: {type(value).__name__}")
    names = _RECORD_FIELDS.get(type(value))
    if names is None:
        raise TypeError(f"unregistered record type: {type(value).__name__}")
    wire = {
        "t": "record",
        "n": type(value).__name__,
        "v": [
                [name, _wire(getattr(value, name, None))]
            for name in names
            if name != omitted_field
        ],
    }
    return "sha256:" + hashlib.sha256(
        _PREFIX + schema.encode("ascii") + b"\0" + _json_bytes(wire)
    ).hexdigest()


def _claim_factory(cls: type[object], *args: object, **kwargs: object) -> object:
    _ensure_registries()
    declared = _RECORD_FIELDS.get(cls)
    if declared is None or "claim_id" not in declared:
        raise TypeError("claim factory requires a registered claim record")
    payload_names = tuple(name for name in declared if name != "claim_id")
    if args and kwargs:
        raise TypeError("claim factory accepts positional or keyword fields, not both")
    optional_defaults = {
        field.name: field.default
        for field in fields(cls)
        if field.default is not MISSING
    }
    if args:
        if len(args) == len(payload_names) - 1 and "retirement_catalog" in payload_names:
            args = (*args, None)
        if len(args) != len(payload_names):
            raise TypeError("claim factory received the wrong number of fields")
        kwargs = dict(zip(payload_names, args))
    elif set(kwargs) != set(payload_names):
            missing = set(payload_names) - set(kwargs)
            if missing and missing <= set(optional_defaults):
                kwargs.update({name: optional_defaults[name] for name in missing})
            else:
                raise TypeError("claim factory requires every non-ID field exactly once")
    raw = object.__new__(cls)
    for name in payload_names:
        object.__setattr__(raw, name, kwargs[name])
    object.__setattr__(raw, "claim_id", "sha256:" + "0" * 64)
    object.__setattr__(raw, "claim_id", claim_id(raw))
    try:
        cls.__post_init__(raw)
    except (TypeError, ValueError):
        try:
            normalized_id = claim_id(raw)
        except (TypeError, ValueError):
            raise
        if normalized_id == raw.claim_id:
            raise
        kwargs = {name: getattr(raw, name) for name in payload_names}
        kwargs["claim_id"] = normalized_id
        return cls(**kwargs)
    return raw


def _evidence_factory(cls: type[object], *args: object, **kwargs: object) -> object:
    _ensure_registries()
    declared = _RECORD_FIELDS.get(cls)
    if declared is None or "evidence_id" not in declared:
        raise TypeError("evidence factory requires a registered evidence record")
    payload_names = tuple(name for name in declared if name != "evidence_id")
    if args and kwargs:
        raise TypeError("evidence factory accepts positional or keyword fields, not both")
    if args:
        if len(args) != len(payload_names):
            raise TypeError("evidence factory received the wrong number of fields")
        kwargs = dict(zip(payload_names, args))
    elif set(kwargs) != set(payload_names):
        raise TypeError("evidence factory requires every non-ID field exactly once")
    raw = object.__new__(cls)
    for name in payload_names:
        object.__setattr__(raw, name, kwargs[name])
    object.__setattr__(raw, "evidence_id", "sha256:" + "0" * 64)
    object.__setattr__(raw, "evidence_id", evidence_id(raw))
    try:
        cls.__post_init__(raw)
    except (TypeError, ValueError):
        try:
            normalized_id = evidence_id(raw)
        except (TypeError, ValueError):
            raise
        if normalized_id == raw.evidence_id:
            raise
        kwargs = {name: getattr(raw, name) for name in payload_names}
        kwargs["evidence_id"] = normalized_id
        return cls(**kwargs)
    return raw


def _justification_factory(cls: type[object], **kwargs: object) -> object:
    _ensure_registries()
    names = _RECORD_FIELDS.get(cls)
    if cls.__name__ != "AuthorityJustification" or names is None:
        raise TypeError("justification factory requires AuthorityJustification")
    payload = {name: kwargs[name] for name in names if name != "justification_id"}
    if set(kwargs) != set(payload):
        raise TypeError("justification factory accepts only non-ID fields")
    raw = object.__new__(cls)
    for name, value in payload.items():
        object.__setattr__(raw, name, value)
    object.__setattr__(raw, "justification_id", "sha256:" + "0" * 64)
    return cls(justification_id=justification_id(raw), **payload)


def _case_factory(cls: type[object], **kwargs: object) -> object:
    _ensure_registries()
    names = _RECORD_FIELDS.get(cls)
    if cls.__name__ != "SemanticSafetyCase" or names is None:
        raise TypeError("case factory requires SemanticSafetyCase")
    optional_defaults = {
        "detached_dead_handler_component_phase_results": (),
        "terminal_cycle_phase_results": (),
    }
    payload_names = tuple(name for name in names if name != "case_id")
    required_names = set(payload_names) - set(optional_defaults)
    if set(kwargs) - set(payload_names) or required_names - set(kwargs):
        raise TypeError("case factory accepts only non-ID fields")
    payload = {
        name: kwargs.get(name, optional_defaults[name])
        if name in optional_defaults
        else kwargs[name]
        for name in payload_names
    }
    raw = object.__new__(cls)
    for name, value in payload.items():
        object.__setattr__(raw, name, value)
    object.__setattr__(raw, "case_id", "sha256:" + "0" * 64)
    return cls(case_id=case_id(raw), **payload)


def _operand_projection(value: object) -> object:
    if value is None:
        return None
    if type(value) is not MopSnapshot:
        raise TypeError("semantic graph requires MopSnapshot operands")
    return MopRecord(
        value.t, value.raw_operand_type, value.kind, value.size, value.value,
        value.stkoff, value.reg, value.block_ref, value.gaddr, value.lvar_off,
        value.lvar_stkoff, value.switch_cases, value.stack_refs, value.sub_kind,
        value.sub_value_op_kind, value.sub_raw_opcode, value.sub_predicate_kind,
        _operand_projection(value.sub_l), _operand_projection(value.sub_r),
        tuple(_operand_projection(item) for item in value.args),
    )


def _instruction_projection(value: object) -> object:
    if type(value) is not InsnSnapshot:
        raise TypeError("semantic graph requires InsnSnapshot instructions")
    return InsnRecord(
        value.opcode, value.raw_opcode, value.kind, value.ea, value.native_ea,
        value.value_op_kind, value.control_transfer_kind, value.call_kind,
        value.predicate_kind, value.branch_predicate, value.compare_width,
        value.is_conditional_jump, value.is_unconditional_jump, value.is_call,
        _operand_projection(value.l), _operand_projection(value.r), _operand_projection(value.d),
        dict(value.opcode_attrs), hashlib.sha256(value.display_text.encode("utf-8", errors="replace")).hexdigest(),
    )


def _validate_operand_manifest(insn: InsnSnapshot) -> None:
    """Require transitional operand evidence to correspond to typed l/r/d."""

    if type(insn.operands) is not tuple or type(insn.operand_slots) is not tuple:
        raise TypeError("instruction transitional operands must be exact tuples")
    if not insn.operands and not insn.operand_slots:
        return
    if not insn.operands or not insn.operand_slots or len(insn.operands) != len(insn.operand_slots):
        raise ValueError("transitional operands and operand slots must form a complete manifest")
    slot_names = []
    for slot in insn.operand_slots:
        if type(slot) is not tuple or len(slot) != 2 or type(slot[0]) is not str:
            raise ValueError("operand slots must be (name, value) pairs")
        slot_names.append(slot[0])
    if len(set(slot_names)) != len(slot_names) or slot_names != sorted(slot_names, key=("l", "r", "d").index):
        raise ValueError("operand slots must be unique in canonical l/r/d order")
    typed_names = tuple(name for name, operand in (("l", insn.l), ("r", insn.r), ("d", insn.d)) if operand is not None)
    if tuple(slot_names) != typed_names:
        raise ValueError("operand slots must exactly match typed l/r/d operands")


def _graph_projection(graph: object, *, blocks: Mapping[int, BlockSnapshot] | None = None) -> object:
    if type(graph) is not FlowGraph:
        raise TypeError("semantic graph requires FlowGraph")
    snapshot_blocks = graph.blocks if blocks is None else blocks
    block_ids = set(snapshot_blocks)
    if snapshot_blocks and graph.entry_serial not in block_ids:
        raise ValueError("graph entry is not present")
    for serial, block in snapshot_blocks.items():
        if type(block) is not BlockSnapshot or block.serial != serial:
            raise ValueError("graph block mapping key must equal BlockSnapshot.serial")
        if len(set(block.succs)) != len(block.succs) or len(set(block.preds)) != len(block.preds):
            raise ValueError("graph topology must not contain duplicate edges")
        if any(target not in block_ids for target in (*block.succs, *block.preds)):
            raise ValueError("graph topology references an unknown block")
        for target in block.succs:
            if serial not in snapshot_blocks[target].preds:
                raise ValueError("graph topology must be reciprocal")
        for source in block.preds:
            if serial not in snapshot_blocks[source].succs:
                raise ValueError("graph topology must be reciprocal")
        for insn in block.insn_snapshots:
            if type(insn) is not InsnSnapshot:
                raise TypeError("semantic graph requires InsnSnapshot instructions")
            _validate_operand_manifest(insn)
    blocks = []
    for serial, block in sorted(snapshot_blocks.items()):
        if type(block) is not BlockSnapshot:
            raise TypeError("semantic graph requires BlockSnapshot blocks")
        blocks.append(BlockRecord(
            serial, block.block_type, block.raw_block_type, block.kind, block.flags,
            block.start_ea, block.native_start_ea, block.succs, block.preds,
            block.tail_opcode, block.raw_tail_opcode, block.tail_kind,
            tuple(_instruction_projection(insn) for insn in block.insn_snapshots),
        ))
    return GraphRecord(graph.func_ea, graph.entry_serial, tuple(blocks))


def semantic_graph_fingerprint(graph: FlowGraph) -> str:
    return content_id(SEMANTIC_GRAPH_SCHEMA, _graph_projection(graph))


def semantic_graph_fingerprint_cached(
    graph: FlowGraph, blocks: Mapping[int, BlockSnapshot],
) -> str:
    """Fingerprint one already-materialized graph block snapshot."""
    if type(blocks) is not dict:
        raise TypeError("cached graph blocks must be an exact dict")
    return content_id(SEMANTIC_GRAPH_SCHEMA, _graph_projection(graph, blocks=blocks))


__all__ = [
    "BlockRecord", "CLAIM_SCHEMA", "DigestFixture", "DIGEST_FIXTURE_SCHEMA",
    "EVIDENCE_SCHEMA", "GraphRecord", "InsnRecord", "MopRecord", "SEMANTIC_GRAPH_SCHEMA",
    "SUBJECT_SCHEMA", "canonical_bytes", "canonical_decode", "validate_canonical_roundtrip", "claim_id", "content_id",
    "evidence_id", "justification_id", "case_id", "authority_id", "binding_id",
    "bound_unflatten_binding_id",
    "semantic_graph_fingerprint", "semantic_graph_fingerprint_cached",
    "semantic_graph_inventory_digest", "subject_id",
]
