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
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentComputedBranchNormalization,
    FragmentConditionalSelectEnvelope,
    FragmentDirectTransferRewrite,
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
class RhadDirectRoute:
    """One reference direct route replacing an imported indirect transfer."""

    operation_id: str
    source_block_id: str
    transfer_ea: int
    owner_anchor_ea: int
    direct_target_block_id: str
    owned_corridor_instruction_eas: tuple[int, ...]
    imported_closure_block_ids: tuple[str, ...]
    boundary_exit_eas: tuple[int, ...]
    phase: RhadReferencePhase
    depends_on: tuple[str, ...] = ()
    category: RhadOperationCategory = RhadOperationCategory.DIRECT_ROUTE

    def __post_init__(self) -> None:
        for field_name in (
            "operation_id",
            "source_block_id",
            "direct_target_block_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name.replace("_", " ")),
            )
        if not self.operation_id.startswith("route:"):
            raise RhadCompilerRejection(
                "Rhad direct operation id requires route-proof identity"
            )
        for field_name in ("transfer_ea", "owner_anchor_ea"):
            object.__setattr__(
                self,
                field_name,
                _native_ea(getattr(self, field_name), field_name.replace("_", " ")),
            )
        if not isinstance(self.phase, RhadReferencePhase):
            raise TypeError("Rhad direct route requires a reference phase")
        if self.category is not RhadOperationCategory.DIRECT_ROUTE:
            raise RhadCompilerRejection(
                "Rhad direct route requires its direct category"
            )
        corridor = _ordered_unique_eas(
            tuple(self.owned_corridor_instruction_eas),
            "Rhad owned corridor",
        )
        if corridor[-1] != int(self.transfer_ea) or int(self.owner_anchor_ea) != int(
            self.transfer_ea
        ):
            raise RhadCompilerRejection(
                "Rhad direct corridor must end at its owned indirect transfer"
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
        object.__setattr__(self, "owned_corridor_instruction_eas", corridor)
        object.__setattr__(self, "imported_closure_block_ids", closure)
        object.__setattr__(self, "boundary_exit_eas", boundaries)
        object.__setattr__(self, "depends_on", dependencies)


RhadReferenceOperation = RhadConditionalRoute | RhadDirectRoute


@dataclass(frozen=True, slots=True)
class RhadReferenceLedger:
    """Immutable compiler input for one reference-ordered fragment batch."""

    ledger_id: str
    function_ea: int
    evidence_generation: int
    base_plan: FragmentPlan
    reference_oracle_run: RouteOracleRun
    operations: tuple[RhadReferenceOperation, ...]
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
            not isinstance(operation, (RhadConditionalRoute, RhadDirectRoute))
            for operation in operations
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

    imported_blocks = tuple(
        block for block in plan.blocks if block.role is FragmentBlockRole.IMPORTED
    )
    imported_ids = {block.block_id for block in imported_blocks}
    closure_ids = {
        block_id
        for operation in ledger.operations
        for block_id in operation.imported_closure_block_ids
    }
    if closure_ids != imported_ids:
        missing = tuple(sorted(imported_ids - closure_ids))
        foreign = tuple(sorted(closure_ids - imported_ids))
        raise RhadCompilerRejection(
            "Rhad operation closure union differs from the portable base fragment: "
            f"missing={missing!r} foreign={foreign!r}"
        )
    internalized_exit_eas = {int(block.semantic_anchor_ea) for block in imported_blocks}
    derived_boundary_exit_eas = tuple(
        sorted(
            {
                int(boundary_ea)
                for operation in ledger.operations
                for boundary_ea in operation.boundary_exit_eas
            }
            - internalized_exit_eas
        )
    )
    if derived_boundary_exit_eas != ledger.required_boundary_exit_eas:
        raise RhadCompilerRejection(
            "Rhad boundary exits differ from derived batch authority"
        )


def _reference_payload(
    ledger: RhadReferenceLedger,
    route: RhadReferenceOperation,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "boundary_exit_eas": list(route.boundary_exit_eas),
        "evidence_generation": int(ledger.evidence_generation),
        "function_ea": int(ledger.function_ea),
        "imported_closure_block_ids": list(route.imported_closure_block_ids),
        "operation_category": route.category.value,
        "operation_id": route.operation_id,
        "owned_corridor_instruction_eas": list(route.owned_corridor_instruction_eas),
        "reference_phase": route.phase.value,
        "reference_provenance": dict(ledger.reference_provenance),
        "transfer_ea": int(route.transfer_ea),
    }
    if isinstance(route, RhadConditionalRoute):
        payload.update(
            {
                "comparison_constant": int(route.comparison_constant),
                "condition_producer_ea": int(route.condition_producer_ea),
                "false_target_block_id": route.false_target_block_id,
                "predicate_kind": route.predicate_kind.value,
                "true_target_block_id": route.true_target_block_id,
            }
        )
    elif isinstance(route, RhadDirectRoute):
        payload["direct_target_block_id"] = route.direct_target_block_id
    else:
        raise RhadCompilerRejection(
            f"Rhad operation type is unsupported: {type(route).__name__}"
        )
    return payload


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
    if any(
        target_id not in route.imported_closure_block_ids
        or block_by_id[target_id].role is not FragmentBlockRole.IMPORTED
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


def _compile_direct_route(
    ledger: RhadReferenceLedger,
    route: RhadDirectRoute,
) -> FragmentOperation:
    plan = ledger.base_plan
    block_by_id = {block.block_id: block for block in plan.blocks}
    required_block_ids = {
        route.source_block_id,
        route.direct_target_block_id,
        *route.imported_closure_block_ids,
    }
    missing = tuple(sorted(required_block_ids - set(block_by_id)))
    if missing:
        raise RhadCompilerRejection(
            "Rhad direct route block binding is incomplete: " + ", ".join(missing)
        )
    source = block_by_id[route.source_block_id]
    if (
        source.role is not FragmentBlockRole.IMPORTED
        or source.materialization is not FragmentBlockMaterialization.IMPORT_NATIVE
        or source.stable_identity is None
        or source.native_body_id is None
    ):
        raise RhadCompilerRejection(
            "Rhad direct route source must be an imported native-body identity"
        )
    native_body = next(
        (body for body in plan.native_bodies if body.body_id == source.native_body_id),
        None,
    )
    if native_body is None or route.operation_id not in native_body.proof_ids:
        raise RhadCompilerRejection(
            "Rhad direct route source lacks native-body operation proof"
        )
    if any(
        not any(
            int(native_range.start_ea) <= int(corridor_ea) < int(native_range.end_ea)
            for native_range in native_body.native_ranges
        )
        for corridor_ea in route.owned_corridor_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad direct route corridor lies outside its native body"
        )
    if (
        plan.work_item_scope is None
        or route.operation_id not in plan.work_item_scope.selected_obligation_ids
    ):
        raise RhadCompilerRejection(
            "Rhad direct route is absent from frontend work-item authority"
        )
    if not source.stable_identity.native_ranges.contains(route.transfer_ea):
        raise RhadCompilerRejection(
            "Rhad direct transfer lies outside its imported source identity"
        )
    target = block_by_id[route.direct_target_block_id]
    if (
        route.direct_target_block_id not in route.imported_closure_block_ids
        or target.role is not FragmentBlockRole.IMPORTED
        or target.stable_identity is None
    ):
        raise RhadCompilerRejection(
            "Rhad direct target must belong to its imported closure"
        )
    delivery_region = next(
        interval
        for interval in source.stable_identity.native_ranges.intervals
        if int(interval.start_ea) <= int(route.transfer_ea) < int(interval.end_ea)
    )
    target_ea = int(target.semantic_anchor_ea)
    payload = _reference_payload(ledger, route)
    reference_route = ReferenceRouteRewrite(
        route_id=route.operation_id,
        function_ea=int(ledger.function_ea),
        owner_ea=int(route.owner_anchor_ea),
        rewrite_anchor_ea=int(route.transfer_ea),
        corridor=tuple(
            (int(interval.start_ea), int(interval.end_ea))
            for interval in source.stable_identity.native_ranges.intervals
        ),
        reference_phase=route.phase.value,
        original_transfer_kind=SemanticTransferKind.INDIRECT,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=target_ea,
        reference_ledger_identity=ledger.ledger_id,
        reference_ledger_json=json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return FragmentOperation(
        operation_id=route.operation_id,
        source_block_id=route.source_block_id,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=route.direct_target_block_id,
            ),
        ),
        direct_transfer_rewrite=FragmentDirectTransferRewrite(
            route_proof_id=route.operation_id.removeprefix("route:"),
            owner_identity=source.stable_identity,
            owner_anchor_ea=int(route.owner_anchor_ea),
            rewrite_anchor_ea=int(route.transfer_ea),
            delivery_region=delivery_region,
            proof_corridor_instruction_eas=route.owned_corridor_instruction_eas,
            superseded_instruction_eas=(int(route.transfer_ea),),
        ),
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=reference_route,
            candidate_rewrite_anchor_ea=int(route.transfer_ea),
        ),
    )


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
    operations: list[FragmentOperation] = []
    corridors: list[FragmentFlagCorridor] = []
    for operation in ledger.operations:
        if isinstance(operation, RhadConditionalRoute):
            compiled_operation, corridor = _compile_conditional_route(
                ledger,
                operation,
            )
            operations.append(compiled_operation)
            corridors.append(corridor)
        elif isinstance(operation, RhadDirectRoute):
            operations.append(_compile_direct_route(ledger, operation))
        else:
            raise RhadCompilerRejection(
                f"Rhad operation type is unsupported: {type(operation).__name__}"
            )
    return replace(
        ledger.base_plan,
        plan_id=f"rhad-reference-compiler:{ledger.ledger_id}",
        atomic_group_id=ledger.ledger_id,
        operations=tuple(operations),
        flag_corridors=tuple(ledger.base_plan.flag_corridors) + tuple(corridors),
        reference_oracle_run=ledger.reference_oracle_run,
    )


__all__ = [
    "EXPECTED_REFERENCE_PHASE_ORDER",
    "RhadCompilerRejection",
    "RhadConditionalRoute",
    "RhadDirectRoute",
    "RhadOperationCategory",
    "RhadReferenceLedger",
    "RhadReferenceOperation",
    "RhadReferencePhase",
    "compile_rhad_reference_fragment",
]
