"""Compile serial-free Rhad reference operations into portable fragments.

This module is deliberately IDA-free. It validates reference evidence against
an already portable base fragment and emits current ``FragmentPlan`` authority;
live binding and mutation remain backend responsibilities.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
import json

from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    RouteOracleRun,
    SemanticTransferKind,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.transforms.fragment_plan import (
    FragmentBlockRole,
    FragmentComputedBranchNormalization,
    FragmentConditionalSelectEnvelope,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentOperation,
    FragmentPlan,
    FragmentReferenceRouteAuthority,
    FragmentValueSite,
)


class RhadCompilerRejection(ValueError):
    """Portable reference evidence is incomplete, stale, or unsupported."""


class RhadReferencePhase(str, Enum):
    """Ordered phases used by the pinned Rhad reference implementation."""

    INDIRECT_JUMP_RECONSTRUCTION = "indirect_jump_reconstruction"
    CONSTANT_MATERIALIZATION = "constant_materialization"
    DISPATCHER_ELIMINATION = "dispatcher_elimination"


class RhadOperationCategory(str, Enum):
    """Portable reference-operation categories inventoried for later slices."""

    DIRECT_ROUTE = "direct_route"
    CONDITIONAL_ROUTE = "conditional_route"
    CONSTANT_MATERIALIZATION = "constant_materialization"
    MATERIALIZED_PREDICATE = "materialized_predicate"
    ORDERED_SIDE_EFFECT_CORRIDOR = "ordered_side_effect_corridor"


EXPECTED_REFERENCE_PHASE_ORDER = (
    RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    RhadReferencePhase.CONSTANT_MATERIALIZATION,
    RhadReferencePhase.DISPATCHER_ELIMINATION,
)


def _identifier(value: str, description: str) -> str:
    normalized = str(value).strip()
    if not normalized:
        raise RhadCompilerRejection(f"{description} must not be empty")
    return normalized


def _native_ea(value: int, description: str) -> int:
    normalized = int(value)
    if not 0 <= normalized < 0xFFFFFFFFFFFFFFFF:
        raise RhadCompilerRejection(f"{description} must be a native EA")
    return normalized


def _ordered_unique_eas(values: tuple[int, ...], description: str) -> tuple[int, ...]:
    normalized = tuple(_native_ea(value, description) for value in values)
    if not normalized or normalized != tuple(sorted(set(normalized))):
        raise RhadCompilerRejection(f"{description} requires ordered unique native EAs")
    return normalized


def _unique_identifiers(
    values: tuple[str, ...],
    description: str,
) -> tuple[str, ...]:
    normalized = tuple(_identifier(value, description) for value in values)
    if not normalized or len(set(normalized)) != len(normalized):
        raise RhadCompilerRejection(f"{description} requires unique identities")
    return normalized


@dataclass(frozen=True, slots=True)
class RhadConditionalRoute:
    """One reference conditional route with explicit native orientation."""

    operation_id: str
    source_block_id: str
    transfer_ea: int
    predicate_anchor_ea: int
    normalization_start_ea: int
    condition_producer_ea: int
    conditional_select_ea: int
    selected_value_block_id: str
    join_block_id: str
    observed_predicate_kind: PredicateKind
    predicate_kind: PredicateKind
    true_target_block_id: str
    false_target_block_id: str
    comparison_constant: int
    owned_corridor_instruction_eas: tuple[int, ...]
    imported_closure_block_ids: tuple[str, ...]
    boundary_exit_eas: tuple[int, ...]
    flag_corridor_id: str
    phase: RhadReferencePhase
    depends_on: tuple[str, ...] = ()
    category: RhadOperationCategory = RhadOperationCategory.CONDITIONAL_ROUTE

    def __post_init__(self) -> None:
        for field_name in (
            "operation_id",
            "source_block_id",
            "selected_value_block_id",
            "join_block_id",
            "true_target_block_id",
            "false_target_block_id",
            "flag_corridor_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name.replace("_", " ")),
            )
        for field_name in (
            "transfer_ea",
            "predicate_anchor_ea",
            "normalization_start_ea",
            "condition_producer_ea",
            "conditional_select_ea",
        ):
            object.__setattr__(
                self,
                field_name,
                _native_ea(getattr(self, field_name), field_name.replace("_", " ")),
            )
        if not isinstance(
            self.observed_predicate_kind, PredicateKind
        ) or not isinstance(
            self.predicate_kind,
            PredicateKind,
        ):
            raise TypeError("Rhad conditional route requires portable predicates")
        if not isinstance(self.phase, RhadReferencePhase):
            raise TypeError("Rhad conditional route requires a reference phase")
        if self.category is not RhadOperationCategory.CONDITIONAL_ROUTE:
            raise RhadCompilerRejection(
                "Rhad conditional route requires its conditional category"
            )
        comparison_constant = int(self.comparison_constant)
        if not 0 <= comparison_constant <= 0xFFFFFFFFFFFFFFFF:
            raise RhadCompilerRejection(
                "Rhad conditional comparison constant is out of range"
            )
        corridor = _ordered_unique_eas(
            tuple(self.owned_corridor_instruction_eas),
            "Rhad owned corridor",
        )
        required_corridor_eas = {
            int(self.condition_producer_ea),
            int(self.predicate_anchor_ea),
            int(self.conditional_select_ea),
            int(self.transfer_ea),
        }
        if not required_corridor_eas.issubset(corridor):
            raise RhadCompilerRejection(
                "Rhad owned corridor lost its producer, predicate, select, or transfer"
            )
        if not (
            self.condition_producer_ea < self.predicate_anchor_ea < self.transfer_ea
            and self.normalization_start_ea == self.predicate_anchor_ea
        ):
            raise RhadCompilerRejection(
                "Rhad conditional normalization anchors are not ordered"
            )
        if self.true_target_block_id == self.false_target_block_id:
            raise RhadCompilerRejection("Rhad conditional route requires two arms")
        if self.selected_value_block_id == self.join_block_id:
            raise RhadCompilerRejection(
                "Rhad conditional select requires distinct selected and join blocks"
            )
        closure = _unique_identifiers(
            tuple(self.imported_closure_block_ids),
            "Rhad imported closure",
        )
        boundaries = _ordered_unique_eas(
            tuple(self.boundary_exit_eas),
            "Rhad boundary exits",
        )
        dependencies = tuple(
            _identifier(value, "Rhad dependency") for value in self.depends_on
        )
        if len(set(dependencies)) != len(dependencies):
            raise RhadCompilerRejection("Rhad operation dependencies must be unique")
        object.__setattr__(self, "comparison_constant", comparison_constant)
        object.__setattr__(self, "owned_corridor_instruction_eas", corridor)
        object.__setattr__(self, "imported_closure_block_ids", closure)
        object.__setattr__(self, "boundary_exit_eas", boundaries)
        object.__setattr__(self, "depends_on", dependencies)


@dataclass(frozen=True, slots=True)
class RhadReferenceLedger:
    """Immutable compiler input for one reference-ordered fragment batch."""

    ledger_id: str
    function_ea: int
    evidence_generation: int
    base_plan: FragmentPlan
    reference_oracle_run: RouteOracleRun
    operations: tuple[RhadConditionalRoute, ...]
    required_boundary_exit_eas: tuple[int, ...]
    reference_provenance: Mapping[str, object]
    unsupported_shape_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        ledger_id = _identifier(self.ledger_id, "Rhad ledger id")
        function_ea = _native_ea(self.function_ea, "Rhad function")
        generation = int(self.evidence_generation)
        if generation < 0:
            raise RhadCompilerRejection("Rhad evidence generation must be non-negative")
        if not isinstance(self.base_plan, FragmentPlan):
            raise TypeError("Rhad ledger requires a portable FragmentPlan")
        if not isinstance(self.reference_oracle_run, RouteOracleRun):
            raise TypeError("Rhad ledger requires a reference oracle run")
        operations = tuple(self.operations)
        if not operations or any(
            not isinstance(operation, RhadConditionalRoute) for operation in operations
        ):
            raise RhadCompilerRejection(
                "Rhad ledger requires admitted reference operations"
            )
        operation_ids = tuple(operation.operation_id for operation in operations)
        if len(set(operation_ids)) != len(operation_ids):
            raise RhadCompilerRejection("Rhad ledger operation ids must be unique")
        boundaries = _ordered_unique_eas(
            tuple(self.required_boundary_exit_eas),
            "Rhad required boundary exits",
        )
        provenance = dict(self.reference_provenance)
        if not provenance:
            raise RhadCompilerRejection("Rhad ledger requires reference provenance")
        unsupported = tuple(
            _identifier(value, "Rhad unsupported shape")
            for value in self.unsupported_shape_ids
        )
        object.__setattr__(self, "ledger_id", ledger_id)
        object.__setattr__(self, "function_ea", function_ea)
        object.__setattr__(self, "evidence_generation", generation)
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "required_boundary_exit_eas", boundaries)
        object.__setattr__(self, "reference_provenance", provenance)
        object.__setattr__(self, "unsupported_shape_ids", unsupported)


def _validate_ledger(
    ledger: RhadReferenceLedger,
    *,
    expected_evidence_generation: int | None,
) -> None:
    if expected_evidence_generation is not None and int(
        expected_evidence_generation
    ) != int(ledger.evidence_generation):
        raise RhadCompilerRejection(
            "Rhad evidence generation differs from current lifecycle generation"
        )
    if ledger.unsupported_shape_ids:
        raise RhadCompilerRejection(
            "Rhad reference shapes are not admitted: "
            + ", ".join(ledger.unsupported_shape_ids)
        )
    plan = ledger.base_plan
    run = ledger.reference_oracle_run
    if (
        int(plan.native_key.function_rva) != int(ledger.function_ea)
        or int(run.function_ea) != int(ledger.function_ea)
        or plan.native_key.input_identity.lower()
        != f"sha256:{run.candidate_binary_sha256.lower()}"
    ):
        raise RhadCompilerRejection(
            "Rhad ledger, native key, and reference run identify different inputs"
        )
    known_operations: set[str] = set()
    last_phase_index = -1
    phase_index = {
        phase: index for index, phase in enumerate(EXPECTED_REFERENCE_PHASE_ORDER)
    }
    for operation in ledger.operations:
        missing_dependencies = tuple(
            dependency
            for dependency in operation.depends_on
            if dependency not in known_operations
        )
        if missing_dependencies:
            raise RhadCompilerRejection(
                "Rhad operation dependency is missing or out of order: "
                + ", ".join(missing_dependencies)
            )
        current_phase_index = phase_index[operation.phase]
        if current_phase_index < last_phase_index:
            raise RhadCompilerRejection("Rhad reference phase order regressed")
        known_operations.add(operation.operation_id)
        last_phase_index = current_phase_index


def _reference_payload(
    ledger: RhadReferenceLedger,
    route: RhadConditionalRoute,
) -> dict[str, object]:
    return {
        "boundary_exit_eas": list(route.boundary_exit_eas),
        "comparison_constant": int(route.comparison_constant),
        "condition_producer_ea": int(route.condition_producer_ea),
        "evidence_generation": int(ledger.evidence_generation),
        "false_target_block_id": route.false_target_block_id,
        "function_ea": int(ledger.function_ea),
        "imported_closure_block_ids": list(route.imported_closure_block_ids),
        "operation_category": route.category.value,
        "operation_id": route.operation_id,
        "owned_corridor_instruction_eas": list(route.owned_corridor_instruction_eas),
        "predicate_kind": route.predicate_kind.value,
        "reference_phase": route.phase.value,
        "reference_provenance": dict(ledger.reference_provenance),
        "transfer_ea": int(route.transfer_ea),
        "true_target_block_id": route.true_target_block_id,
    }


def _compile_conditional_route(
    ledger: RhadReferenceLedger,
    route: RhadConditionalRoute,
) -> tuple[FragmentOperation, FragmentFlagCorridor]:
    plan = ledger.base_plan
    block_by_id = {block.block_id: block for block in plan.blocks}
    required_block_ids = {
        route.source_block_id,
        route.selected_value_block_id,
        route.join_block_id,
        route.true_target_block_id,
        route.false_target_block_id,
        *route.imported_closure_block_ids,
    }
    missing = tuple(sorted(required_block_ids - set(block_by_id)))
    if missing:
        raise RhadCompilerRejection(
            "Rhad route block binding is incomplete: " + ", ".join(missing)
        )
    source = block_by_id[route.source_block_id]
    if (
        source.role is not FragmentBlockRole.REPLACEMENT
        or source.stable_identity is None
    ):
        raise RhadCompilerRejection(
            "Rhad route source must be a portable replacement identity"
        )
    if any(
        not source.stable_identity.native_ranges.contains(ea)
        for ea in route.owned_corridor_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad route corridor lies outside its source identity"
        )
    imported_ids = tuple(
        block.block_id
        for block in plan.blocks
        if block.role is FragmentBlockRole.IMPORTED
    )
    if imported_ids != route.imported_closure_block_ids:
        raise RhadCompilerRejection(
            "Rhad imported closure differs from the portable base fragment"
        )
    if route.boundary_exit_eas != ledger.required_boundary_exit_eas:
        raise RhadCompilerRejection("Rhad boundary exits differ from ledger authority")
    if any(
        block_by_id[target_id].role is not FragmentBlockRole.IMPORTED
        for target_id in (route.true_target_block_id, route.false_target_block_id)
    ):
        raise RhadCompilerRejection(
            "Rhad conditional targets must belong to the imported closure"
        )
    true_target_ea = int(block_by_id[route.true_target_block_id].semantic_anchor_ea)
    false_target_ea = int(block_by_id[route.false_target_block_id].semantic_anchor_ea)
    payload = _reference_payload(ledger, route)
    reference_route = ReferenceRouteRewrite(
        route_id=route.operation_id,
        function_ea=int(ledger.function_ea),
        owner_ea=int(route.predicate_anchor_ea),
        rewrite_anchor_ea=int(route.predicate_anchor_ea),
        corridor=tuple(
            (int(interval.start_ea), int(interval.end_ea))
            for interval in source.stable_identity.native_ranges.intervals
        ),
        reference_phase=route.phase.value,
        original_transfer_kind=SemanticTransferKind.INDIRECT,
        final_transfer_kind=SemanticTransferKind.CONDITIONAL,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        predicate_kind=route.predicate_kind.value,
        reference_ledger_identity=ledger.ledger_id,
        reference_ledger_json=json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    normalization = FragmentComputedBranchNormalization(
        predicate_kind=route.predicate_kind,
        normalization_start_ea=int(route.normalization_start_ea),
        condition_producer_ea=int(route.condition_producer_ea),
        unresolved_transfer_ea=int(route.transfer_ea),
        conditional_select_envelope=FragmentConditionalSelectEnvelope(
            predicate_ea=int(route.conditional_select_ea),
            observed_predicate_kind=route.observed_predicate_kind,
            selected_value_block_id=route.selected_value_block_id,
            join_block_id=route.join_block_id,
        ),
    )
    operation = FragmentOperation(
        operation_id=route.operation_id,
        source_block_id=route.source_block_id,
        predicate_anchor_ea=int(route.predicate_anchor_ea),
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                target_block_id=route.true_target_block_id,
            ),
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                target_block_id=route.false_target_block_id,
            ),
        ),
        computed_branch_normalization=normalization,
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=reference_route,
            candidate_rewrite_anchor_ea=int(route.predicate_anchor_ea),
        ),
    )
    value_id = f"rhad-flags@0x{route.condition_producer_ea:X}"
    flag_corridor = FragmentFlagCorridor(
        corridor_id=route.flag_corridor_id,
        producer=FragmentValueSite(
            site_id=f"producer@0x{route.condition_producer_ea:X}",
            block_id=route.source_block_id,
            value_id=value_id,
            instruction_ea=int(route.condition_producer_ea),
        ),
        consumer=FragmentValueSite(
            site_id=f"consumer@0x{route.predicate_anchor_ea:X}",
            block_id=route.source_block_id,
            value_id=value_id,
            instruction_ea=int(route.predicate_anchor_ea),
        ),
        block_path=(route.source_block_id,),
        permitted_flag_write_eas=frozenset({int(route.condition_producer_ea)}),
    )
    return operation, flag_corridor


def compile_rhad_reference_fragment(
    ledger: RhadReferenceLedger,
    *,
    expected_evidence_generation: int | None = None,
) -> FragmentPlan:
    """Compile one admitted reference batch into current fragment authority."""
    if not isinstance(ledger, RhadReferenceLedger):
        raise TypeError("Rhad compiler requires a RhadReferenceLedger")
    _validate_ledger(
        ledger,
        expected_evidence_generation=expected_evidence_generation,
    )
    compiled = tuple(
        _compile_conditional_route(ledger, operation) for operation in ledger.operations
    )
    operations = tuple(operation for operation, _corridor in compiled)
    corridors = tuple(corridor for _operation, corridor in compiled)
    return replace(
        ledger.base_plan,
        plan_id=f"rhad-reference-compiler:{ledger.ledger_id}",
        atomic_group_id=ledger.ledger_id,
        operations=operations,
        flag_corridors=tuple(ledger.base_plan.flag_corridors) + corridors,
        reference_oracle_run=ledger.reference_oracle_run,
    )


__all__ = [
    "EXPECTED_REFERENCE_PHASE_ORDER",
    "RhadCompilerRejection",
    "RhadConditionalRoute",
    "RhadOperationCategory",
    "RhadReferenceLedger",
    "RhadReferencePhase",
    "compile_rhad_reference_fragment",
]
