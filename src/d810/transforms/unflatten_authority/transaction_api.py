"""Patch-transaction-facing route selection for unflatten authority."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from time import perf_counter
from time import perf_counter_ns
import hashlib
import re

from d810.core.logging import getLogger
from d810.transforms.plan import (
    PatchConditionalRedirect,
    PatchConvertToGoto,
    PatchEdgeSplitCorridor,
    PatchEdgeSplitTrampoline,
    PatchLowerConditionalStateTransition,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchScalarizeLocalAliasAccess,
)
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalRouteMaterialization,
    CanonicalSemanticEvidence,
    RouteRebindVerification,
    SemanticCorridorPoint,
    SemanticLogicalDagEndpoint,
    capture_observed_route_materialization,
    capture_projected_route_materialization,
    capture_source_route_materialization,
)
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.block_identity import stable_block_identity_semantic_anchor
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.graph_modification import (
    SyntheticCounterBoundCondition,
    SyntheticRegisterNonzeroCondition,
    SyntheticStackValueEqualsCondition,
)
from d810.transforms.cfg_transaction import CfgProjection, PatchStepKind, TransactionAttemptId
from d810.transforms.cfg_transaction import (
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
)
from d810.transforms.patch_binding import (
    BoundPatchPlan,
    ObservedPatchBinding,
    iter_refs,
    validate_bound_patch_plan,
    validate_observed_patch_binding,
)
from d810.transforms.unflatten_authority import bind as authority_bind
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority import producer_api
from d810.transforms.unflatten_authority.evaluate import (
    build_semantic_loss_ledger,
    build_projected_semantic_loss_ledger,
    build_semantic_case,
    evaluate_case,
)
from d810.transforms.unflatten_authority import gates
from d810.transforms.unflatten_authority.gates import (
    GenericEffectfulGateFacts,
    GenericCfgGateBundle,
    validate_generic_cfg_gate_bundle,
)
from d810.transforms.unflatten_authority.diagnostics import PhaseTimings, phase_observation
from d810.transforms.unflatten_authority.views import compatibility_projection
from d810.transforms.exit_path_liveness_policy import exit_path_blocks_live_violations
from .runtime_authority import rebind_route_evidence

from .canonical_session import (
    CanonicalSessionPhase,
    _canonical_validation_session,
)
from .proposal import (
    CanonicalPatchStepDescriptor,
    _entry_liveness_route_proof_rejection_detail,
    canonical_patch_step_descriptor,
    canonical_patch_step_descriptors,
)

# These aliases are the only authority types/projections that the live patch
# transaction may consume.  Keep their implementation imports behind this
# facade so the vendor transaction cannot reach authority submodules directly.
UnflattenAuthorityNotApplicable = model.UnflattenAuthorityNotApplicable
UnflattenAuthorityPreparationAccepted = model.UnflattenAuthorityPreparationAccepted
UnflattenAuthorityPreparationRejected = model.UnflattenAuthorityPreparationRejected
UnflattenAuthorityBindingAccepted = model.UnflattenAuthorityBindingAccepted
UnflattenAuthorityBindingRejected = model.UnflattenAuthorityBindingRejected
UnflattenAuthorityVerdict = model.UnflattenAuthorityVerdict


def _validate_observed_logical_occurrence_provenance(
    inventory: model.SemanticGraphInventory,
) -> None:
    """Require every moved logical binding to retain its binder mint."""

    for binding in inventory.bindings:
        occurrence = binding.observed_logical_occurrence
        if occurrence is not None:
            authority_bind._validate_observed_logical_endpoint_occurrence(
                occurrence,
            )


@dataclass(frozen=True, slots=True)
class _CandidateIdentityResolution:
    """One private, immutable candidate-identity classification result."""

    serial_bindings: tuple[tuple[object, int], ...]
    synthetic_tail_origins: tuple[tuple[int, int], ...]
    logical_endpoint_occurrences: tuple[
        model.ObservedLogicalEndpointOccurrence, ...
    ] = ()
    relocated_stop_tail_receipts: tuple[
        "_ObservedRelocatedStopTailReceipt", ...
    ] = ()


@dataclass(frozen=True, slots=True)
class _ObservedRelocatedStopTailReceipt:
    """One binder-minted allocation tail for a relocated structural STOP.

    Hex-Rays may materialize an otherwise implicit fallthrough to a relocated
    STOP as a final GOTO whose EA is the function allocation coordinate.  This
    receipt is intentionally private and occurrence-bound: its sole consumer
    removes that one allocation origin from the native identity row while the
    GOTO and its CFG edge remain visible in the observed inventory.
    """

    owner_ref: NativeBlockRef
    source_owner_serial: int
    projected_owner_serial: int
    observed_owner_serial: int
    source_stop_serial: int
    projected_stop_serial: int
    observed_stop_serial: int
    synthetic_tail_origin: int
    observed_patch_binding: ObservedPatchBinding


def _instruction_semantics_equal(left, right) -> bool:
    """Compare instruction meaning while retaining phase-local provenance."""
    return replace(left, instruction_ea=None) == replace(right, instruction_ea=None)


def _is_exact_structural_stop(block: BlockSnapshot) -> bool:
    return (
        block.kind is BlockKind.STOP
        and not block.insn_snapshots
        and not block.succs
        and block.start_ea == 0xFFFFFFFFFFFFFFFF
        and not (
            type(block.native_start_ea) is int
            and 0 <= block.native_start_ea < 0xFFFFFFFFFFFFFFFF
        )
    )


def _is_exact_inventory_structural_stop(
    row: model.InventoryBlockObservation,
) -> bool:
    """Recognize the ownerless projected representation of a shifted STOP."""
    return bool(
        row.block_ref is None
        and row.anchor_ea is None
        and row.block_kind is BlockKind.STOP
        and not row.native_instruction_eas
        and not row.instruction_observations
        and not row.successor_serials
        and row.transfer_ea is None
        and row.graph_start_ea == 0xFFFFFFFFFFFFFFFF
        and row.tail_opcode is None
        and row.raw_tail_opcode is None
        and row.tail_kind is None
    )


def _has_exact_relocated_stop_helper_ownership(
    plan: PatchPlan,
    expected_helpers: tuple[PlanBlockRef, ...],
) -> bool:
    """Require plan-order corridor ownership to cover helpers exactly once."""
    corridor_helper_refs = tuple(
        helper_ref
        for step in plan.steps
        if type(step) is PatchEdgeSplitCorridor
        for helper_ref in step.clone_block_ids
    )
    return bool(
        corridor_helper_refs
        and len(set(corridor_helper_refs)) == len(corridor_helper_refs)
        and corridor_helper_refs == expected_helpers
    )


def _mint_observed_relocated_stop_tail_receipts(
    *,
    blocks: Mapping[int, BlockSnapshot],
    plan: PatchPlan,
    source_rows: tuple[model.InventoryBlockObservation, ...],
    projected_rows: tuple[model.InventoryBlockObservation, ...],
    observed_patch_binding: ObservedPatchBinding,
    planned_serials: Mapping[PlanBlockRef, int],
    function_ea: int,
) -> tuple[_ObservedRelocatedStopTailReceipt, ...]:
    """Mint exact relocated-STOP tail receipts before observed identity bind.

    This is not a general function-entry-origin exception.  It admits only
    the backend shape produced when a corridor insertion relocates the source
    structural STOP, after the exact helper binding for this plan occurrence
    has already been sealed.
    """
    if type(plan) is not PatchPlan or type(observed_patch_binding) is not ObservedPatchBinding:
        raise TypeError("relocated STOP receipt requires exact plan binding")
    validate_observed_patch_binding(observed_patch_binding)
    if observed_patch_binding.bound_plan.plan is not plan:
        raise ValueError("relocated STOP receipt binding is foreign to plan")
    if type(function_ea) is not int or not 0 <= function_ea < 0xFFFFFFFFFFFFFFFF:
        raise ValueError("relocated STOP receipt requires exact function EA")
    if not plan.new_blocks or plan.relocation_map.source_stop is None:
        return ()
    if any(type(ref) is not PlanBlockRef or type(serial) is not int or serial < 0
           for ref, serial in planned_serials.items()):
        raise ValueError("relocated STOP receipt requires exact helper coordinates")
    expected_helpers = tuple(spec.block_id for spec in plan.new_blocks)
    bound_helpers = tuple(
        (ref, serial)
        for ref, serial in observed_patch_binding.bindings
        if type(ref) is PlanBlockRef
    )
    if tuple(ref for ref, _serial in bound_helpers) != expected_helpers:
        logger.debug(
            "relocated STOP receipt declined stage=helper_refs expected=%s bound=%s",
            tuple(ref.local_block_id for ref in expected_helpers),
            tuple(ref.local_block_id for ref, _serial in bound_helpers),
        )
        return ()
    if tuple(bound_helpers) != tuple(planned_serials.items()):
        logger.debug(
            "relocated STOP receipt declined stage=helper_bindings bound=%s planned=%s",
            tuple((ref.local_block_id, serial) for ref, serial in bound_helpers),
            tuple((ref.local_block_id, serial) for ref, serial in planned_serials.items()),
        )
        return ()
    if any(serial not in blocks for _ref, serial in bound_helpers):
        return ()

    stop_ref = plan.relocation_map.source_stop
    if type(stop_ref) is not LogicalBlockRef:
        logger.debug(
            "relocated STOP receipt declined stage=stop_ref_type type=%s",
            type(stop_ref).__name__,
        )
        return ()
    corridor_helper_refs = tuple(
        helper_ref
        for step in plan.steps
        if type(step) is PatchEdgeSplitCorridor
        for helper_ref in step.clone_block_ids
    )
    if not _has_exact_relocated_stop_helper_ownership(plan, expected_helpers):
        logger.debug(
            "relocated STOP receipt declined stage=corridor helpers=%s corridor_helpers=%s",
            tuple(ref.local_block_id for ref in expected_helpers),
            tuple(ref.local_block_id for ref in corridor_helper_refs),
        )
        return ()
    direct_owner_refs = {
        ref
        for descriptor in canonical_patch_step_descriptors(plan)
        for ref in descriptor.owner_refs
    }
    source_by_ref = {row.block_ref: row for row in source_rows if row.block_ref is not None}
    projected_by_ref = {row.block_ref: row for row in projected_rows if row.block_ref is not None}
    source_stop = source_by_ref.get(stop_ref)
    if source_stop is None:
        logger.debug(
            "relocated STOP receipt declined stage=source_stop_binding",
        )
        return ()
    source_stop_serial = source_stop.serial
    expected_helper_rows = tuple(
        (ref, source_stop_serial + offset)
        for offset, ref in enumerate(expected_helpers)
    )
    if tuple(planned_serials.items()) != expected_helper_rows:
        logger.debug(
            "relocated STOP receipt declined stage=helper_interval expected=%s planned=%s",
            tuple((ref.local_block_id, serial) for ref, serial in expected_helper_rows),
            tuple((ref.local_block_id, serial) for ref, serial in planned_serials.items()),
        )
        return ()
    expected_stop_serial = source_stop_serial + len(expected_helpers)
    projected_stop_candidates = tuple(
        row
        for row in projected_rows
        if row.serial == expected_stop_serial
        and _is_exact_inventory_structural_stop(row)
    )
    if len(projected_stop_candidates) != 1:
        logger.debug(
            "relocated STOP receipt declined stage=projected_stop_binding expected=%d candidates=%s",
            expected_stop_serial,
            tuple(
                (row.serial, row.block_ref, row.block_kind.value)
                for row in projected_rows
                if row.serial == expected_stop_serial
            ),
        )
        return ()
    projected_stop = projected_stop_candidates[0]
    if (
        projected_stop.serial != expected_stop_serial
        or any(
            not any(
                row.serial == serial and row.block_ref == ref
                for row in projected_rows
            )
            for ref, serial in expected_helper_rows
        )
    ):
        logger.debug(
            "relocated STOP receipt declined stage=projected_relocation source_stop=%d projected_stop=%d expected_stop=%d projected_helpers=%s",
            source_stop_serial,
            projected_stop.serial,
            source_stop_serial + len(expected_helpers),
            tuple(
                (ref.local_block_id, tuple(row.serial for row in projected_rows if row.block_ref == ref))
                for ref in expected_helpers
            ),
        )
        return ()
    source_blocks = tuple(
        row for row in source_rows
        if type(row.block_ref) is NativeBlockRef
        and row.block_ref not in direct_owner_refs
        and row.successor_serials == (source_stop.serial,)
    )
    if len(source_blocks) != 1:
        logger.debug(
            "relocated STOP receipt declined stage=source_owner candidates=%s stop=%d preds=%s",
            tuple(row.serial for row in source_blocks),
            source_stop.serial,
            source_stop.predecessor_serials,
        )
        return ()
    source_owner = source_blocks[0]
    projected_owner = projected_by_ref.get(source_owner.block_ref)
    if (
        projected_owner is None
        or projected_owner.serial != source_owner.serial
        or projected_owner.successor_serials != (projected_stop.serial,)
        or source_owner.block_kind is not BlockKind.ONE_WAY
        or projected_owner.block_kind is not BlockKind.ONE_WAY
        or source_stop.block_kind is not BlockKind.STOP
        or projected_stop.block_kind is not BlockKind.STOP
        or source_stop.instruction_observations
        or projected_stop.instruction_observations
        or source_stop.successor_serials
        or projected_stop.successor_serials
        or source_stop.predecessor_serials != (source_owner.serial,)
        or projected_stop.predecessor_serials != (projected_owner.serial,)
        or len(source_owner.instruction_observations)
        != len(projected_owner.instruction_observations)
        or any(not _instruction_semantics_equal(left, right) for left, right in zip(
            source_owner.instruction_observations,
            projected_owner.instruction_observations,
            strict=True,
        ))
    ):
        logger.debug(
            "relocated STOP receipt declined stage=projected_owner source_owner=%d projected_owner=%s source_stop=%d projected_stop=%d source_stop_preds=%s projected_stop_preds=%s source_body=%d projected_body=%s source_succ=%s projected_succ=%s",
            source_owner.serial,
            None if projected_owner is None else projected_owner.serial,
            source_stop.serial,
            projected_stop.serial,
            source_stop.predecessor_serials,
            projected_stop.predecessor_serials,
            len(source_owner.instruction_observations),
            None if projected_owner is None else len(projected_owner.instruction_observations),
            source_owner.successor_serials,
            None if projected_owner is None else projected_owner.successor_serials,
        )
        return ()
    candidate_rows: list[_ObservedRelocatedStopTailReceipt] = []
    for observed_owner in blocks.values():
        anchor = (
            observed_owner.native_start_ea
            if observed_owner.native_start_ea is not None else observed_owner.start_ea
        )
        if (
            observed_owner.serial != source_owner.serial
            or anchor != source_owner.anchor_ea
            or observed_owner.kind is not BlockKind.ONE_WAY
        ):
            continue
        if len(observed_owner.succs) != 1 or len(observed_owner.insn_snapshots) != len(source_owner.instruction_observations) + 1:
            continue
        observed_prefix = producer_api.observe_inventory_block(
            replace(observed_owner, insn_snapshots=observed_owner.insn_snapshots[:-1],
                    tail_opcode=(observed_owner.insn_snapshots[-2].opcode if len(observed_owner.insn_snapshots) > 1 else None),
                    raw_tail_opcode=(observed_owner.insn_snapshots[-2].raw_opcode if len(observed_owner.insn_snapshots) > 1 else None),
                    tail_kind=(observed_owner.insn_snapshots[-2].kind if len(observed_owner.insn_snapshots) > 1 else None)),
            owner_ref=source_owner.block_ref,
            owner_anchor_ea=source_owner.anchor_ea,
        ).instruction_observations
        if len(observed_prefix) != len(source_owner.instruction_observations) or any(
            not _instruction_semantics_equal(left, right)
            for left, right in zip(observed_prefix, source_owner.instruction_observations, strict=True)
        ):
            continue
        tail = observed_owner.insn_snapshots[-1]
        if (
            tail.ea != function_ea
            or tail.native_ea != function_ea
            or not _is_exact_unconditional_goto_to(observed_owner, observed_owner.succs[0])
        ):
            continue
        prefix_origins = tuple(
            instruction.native_ea if instruction.native_ea is not None else instruction.ea
            for instruction in observed_owner.insn_snapshots[:-1]
        )
        if (
            function_ea in prefix_origins
            or function_ea in source_owner.native_instruction_eas
            or tuple(sorted(prefix_origins)) != source_owner.native_instruction_eas
        ):
            continue
        observed_stop = blocks.get(observed_owner.succs[0])
        if (
            observed_stop is None
            or not _is_exact_structural_stop(observed_stop)
            or observed_stop.serial != source_stop_serial + len(expected_helpers)
            or observed_stop.preds != (observed_owner.serial,)
        ):
            continue
        candidate_rows.append(_ObservedRelocatedStopTailReceipt(
            source_owner.block_ref,
            source_owner.serial,
            projected_owner.serial,
            observed_owner.serial,
            source_stop.serial,
            projected_stop.serial,
            observed_stop.serial,
            function_ea,
            observed_patch_binding,
        ))
    if len(candidate_rows) != 1:
        logger.debug(
            "relocated STOP receipt declined stage=observed_owner candidates=%s source_owner=%d expected_stop=%d observed_shape=%s",
            tuple(row.observed_owner_serial for row in candidate_rows),
            source_owner.serial,
            source_stop_serial + len(expected_helpers),
            tuple(
                (
                    block.serial,
                    block.kind.value,
                    block.preds,
                    block.succs,
                    len(block.insn_snapshots),
                )
                for block in blocks.values()
                if block.serial in {
                    source_owner.serial,
                    source_stop_serial + len(expected_helpers),
                }
            ),
        )
        return ()
    return tuple(candidate_rows)


def _consume_observed_relocated_stop_tail_receipt(
    receipt: _ObservedRelocatedStopTailReceipt,
    *,
    observed_patch_binding: ObservedPatchBinding,
    owner_ref: object,
    observed_owner_serial: int,
) -> int:
    """Return the single origin authorized by this exact receipt occurrence."""
    if type(receipt) is not _ObservedRelocatedStopTailReceipt:
        raise TypeError("relocated STOP tail receipt must be exact")
    if receipt.observed_patch_binding is not observed_patch_binding:
        raise ValueError("relocated STOP receipt differs from observed binding occurrence")
    if receipt.owner_ref != owner_ref or receipt.observed_owner_serial != observed_owner_serial:
        raise ValueError("relocated STOP receipt differs from observed owner occurrence")
    return receipt.synthetic_tail_origin


def _normalize_observed_relocated_stop_tail_origin(
    observed: model.InventoryBlockObservation,
    *,
    receipt: _ObservedRelocatedStopTailReceipt,
    observed_patch_binding: ObservedPatchBinding,
) -> model.InventoryBlockObservation:
    """Remove only a sealed relocated-STOP allocation origin from one row."""
    origin = _consume_observed_relocated_stop_tail_receipt(
        receipt,
        observed_patch_binding=observed_patch_binding,
        owner_ref=observed.block_ref,
        observed_owner_serial=observed.serial,
    )
    if not observed.instruction_observations:
        raise ValueError("relocated STOP receipt owner has no observed tail")
    tail = observed.instruction_observations[-1]
    if tail.instruction_ea != origin:
        raise ValueError("relocated STOP receipt tail origin differs from observed row")
    if observed.native_instruction_eas.count(origin) != 1:
        raise ValueError("relocated STOP receipt origin is not unique in observed row")
    return replace(
        observed,
        native_instruction_eas=tuple(
            ea for ea in observed.native_instruction_eas if ea != origin
        ),
        instruction_observations=(
            *observed.instruction_observations[:-1],
            replace(tail, instruction_ea=None),
        ),
        transfer_ea=None,
    )


def _admit_relocated_stop_tail_owner(
    serial_by_ref: dict[object, int],
    receipt: _ObservedRelocatedStopTailReceipt,
) -> None:
    """Join a receipt to candidate identities only as its exact owner pair."""
    existing_serial = serial_by_ref.get(receipt.owner_ref)
    existing_ref = next(
        (
            ref for ref, serial in serial_by_ref.items()
            if serial == receipt.observed_owner_serial
        ),
        None,
    )
    if (
        existing_serial not in (None, receipt.observed_owner_serial)
        or existing_ref not in (None, receipt.owner_ref)
    ):
        raise ValueError("relocated STOP owner overlaps another identity")
    if existing_serial is None and existing_ref is None:
        serial_by_ref[receipt.owner_ref] = receipt.observed_owner_serial


def _is_exact_unconditional_goto_to(block: BlockSnapshot, serial: int) -> bool:
    if (
        block.kind is not BlockKind.ONE_WAY
        or block.succs != (serial,)
        or not block.insn_snapshots
    ):
        return False
    tail = block.insn_snapshots[-1]
    block_targets = tuple(
        operand
        for operand in (tail.l, tail.d)
        if operand is not None and operand.kind is OperandKind.BLOCK
    )
    return bool(
        tail.kind is InsnKind.GOTO
        and tail.control_transfer_kind is ControlTransferKind.GOTO
        and tail.is_unconditional_jump
        and not tail.is_conditional_jump
        and not tail.is_call
        and tail.call_kind is None
        and tail.branch_predicate is None
        and tail.predicate_kind is None
        and tail.r is None
        and len(block_targets) == 1
        and block_targets[0].block_ref == serial
        and all(
            operand is None or operand in block_targets
            for operand in (tail.l, tail.d)
        )
    )


def _mint_observed_route_topology_occurrences(
    *,
    blocks: Mapping[int, BlockSnapshot],
    serial_by_ref: Mapping[object, int],
    projected_inventory: model.SemanticGraphInventory | None,
    realization: model.ProjectedRouteRealization | None,
    patch_facts: tuple[model.PatchStepEvidencePayload, ...],
) -> tuple[model.ObservedRouteTopologyOccurrence, ...]:
    """Validate raw observed route transfers once and mint their receipts.

    This is deliberately transaction-side: the evaluator receives only the
    immutable, binder-minted projected pairs and cannot reinterpret backend
    instruction or CFG evidence.
    """
    if projected_inventory is None or realization is None:
        return ()
    model.validate_semantic_graph_inventory(projected_inventory)
    if projected_inventory.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("observed route occurrence requires projected inventory")

    def reciprocal(left: int, right: int) -> bool:
        return (
            left in blocks and right in blocks
            and right in blocks[left].succs
            and left in blocks[right].preds
        )

    def fact_for(row: model.ProjectedRouteRealizationRow):
        expected = {
            PatchStepKind.REDIRECT_GOTO: "PatchRedirectGoto",
            PatchStepKind.CONVERT_TO_GOTO: "PatchConvertToGoto",
            PatchStepKind.LOWER_CONDITIONAL: "PatchLowerConditionalStateTransition",
        }.get(row.plan_step_type)
        if expected is None:
            return None
        matches = tuple(
            fact for fact in patch_facts
            if fact.step_index == row.plan_step_index
            and fact.step_type == expected
            and fact.step_digest == row.plan_step_digest
            and fact.owner_ref == row.source_ref
            and fact.plan_id == realization.plan_id
        )
        return matches[0] if len(matches) == 1 else None

    # Canonical projected subject pairs are reconstructed from the sealed
    # inventory, never from the observed graph.
    subjects_by_ref: dict[object, tuple[str, ...]] = {}
    for subject in projected_inventory.subjects:
        if (
            subject.block_ref is not None
            and subject.role in model.TOPOLOGY_SUBJECT_ROLES
        ):
            subjects_by_ref.setdefault(subject.block_ref, ())
            subjects_by_ref[subject.block_ref] = tuple(sorted({
                *subjects_by_ref[subject.block_ref], subject.subject_id,
            }))
    projected_blocks = {item.serial: item for item in projected_inventory.blocks}
    projected_topology = {
        (item.owner_serial, item.peer_serial): item
        for item in projected_inventory.topology
        if item.kind is model.TopologyIncidenceKind.SUCCESSOR
    }

    def pairs_for(left_ref: object, right_ref: object):
        left = projected_inventory.serial_by_ref.get(left_ref)
        right = projected_inventory.serial_by_ref.get(right_ref)
        if left is None or right is None or (left, right) not in projected_topology:
            return ()
        anchor = projected_topology[(left, right)].source_transfer_ea
        if anchor is None:
            anchor = projected_blocks[left].anchor_ea
        if anchor is None:
            return ()
        left_ids, right_ids = subjects_by_ref.get(left_ref, ()), subjects_by_ref.get(right_ref, ())
        return tuple(sorted({
            model.TopologyEdgeRelation(model.SemanticEdgeRole.DIRECT, a, b, anchor)
            for a in left_ids for b in right_ids
        } | {
            model.TopologyEdgeRelation(model.SemanticEdgeRole.DIRECT, b, a, anchor)
            for a in left_ids for b in right_ids
        }, key=lambda pair: (pair.source_subject_id, pair.target_subject_id, pair.native_edge_anchor_ea)))

    results: list[model.ObservedRouteTopologyOccurrence] = []
    for row in realization.rows:
        relation = row.relation
        if type(relation) not in {
            model.DirectRouteRealization,
            model.LoweredConditionalRouteRealization,
        }:
            continue
        fact = fact_for(row)
        if fact is None:
            continue
        if type(relation) is model.DirectRouteRealization:
            feeder = serial_by_ref.get(relation.feeder.ref)
            target = serial_by_ref.get(relation.new_target.ref)
            if (
                feeder is None or target is None or feeder not in blocks
                or not _is_exact_unconditional_goto_to(blocks[feeder], target)
                or not reciprocal(feeder, target)
            ):
                continue
            pairs = pairs_for(relation.feeder.ref, relation.new_target.ref)
        else:
            arms = {arm.role: arm.target.ref for arm in relation.arms}
            fallthrough = arms[model.SemanticEdgeRole.CONDITIONAL_FALLTHROUGH]
            taken = arms[model.SemanticEdgeRole.CONDITIONAL_TAKEN]
            feeder = serial_by_ref.get(relation.feeder.ref)
            fallthrough_serial = serial_by_ref.get(fallthrough)
            taken_serial = serial_by_ref.get(taken)
            projected_feeder = projected_inventory.serial_by_ref.get(relation.feeder.ref)
            if None in (feeder, fallthrough_serial, taken_serial, projected_feeder):
                continue
            live = blocks.get(feeder)
            projected = projected_blocks.get(projected_feeder)
            if (
                live is None or projected is None
                or live.kind is not BlockKind.TWO_WAY
                or len(live.succs) != 2
                or not live.insn_snapshots or not projected.instruction_observations
            ):
                continue
            # Keep the condition semantics unchanged; the backend may only
            # insert the immediately-adjacent fallthrough GOTO helper.
            live_tail = live.insn_snapshots[-1]
            projected_tail = projected.instruction_observations[-1]
            if (
                live_tail.kind is not InsnKind.COND_JUMP
                or live_tail.control_transfer_kind is not ControlTransferKind.CONDITIONAL_BRANCH
                or projected_tail.predicate_observation is None
                or live_tail.branch_predicate
                != projected_tail.predicate_observation.predicate_kind
                or live.succs[1] != taken_serial
                or not reciprocal(feeder, taken_serial)
            ):
                continue
            if live.succs[0] == fallthrough_serial:
                if not reciprocal(feeder, fallthrough_serial):
                    continue
            else:
                helper = live.succs[0]
                helper_block = blocks.get(helper)
                if (
                    helper != feeder + 1 or helper_block is None
                    or helper in serial_by_ref.values()
                    or helper_block.preds != (feeder,)
                    or helper_block.succs != (fallthrough_serial,)
                    or not _is_exact_unconditional_goto_to(helper_block, fallthrough_serial)
                    or helper_block.insn_snapshots[-1].opcode < 0
                    or helper_block.insn_snapshots[-1].raw_opcode
                    != helper_block.insn_snapshots[-1].opcode
                    or not reciprocal(feeder, helper)
                    or not reciprocal(helper, fallthrough_serial)
                ):
                    continue
            pairs = (*pairs_for(relation.feeder.ref, fallthrough), *pairs_for(relation.feeder.ref, taken))
        if not pairs:
            continue
        results.append(authority_bind.mint_observed_route_topology_occurrence(
            relation_id=relation.relation_id,
            row_id=row.row_id,
            patch_fact=fact,
            normalized_pairs=tuple(sorted(set(pairs), key=lambda pair: (
                pair.source_subject_id, pair.target_subject_id,
                pair.native_edge_anchor_ea,
            ))),
        ))
    return tuple(sorted(results, key=lambda item: item.occurrence_id))


def _lowered_condition_signature(condition: object) -> tuple[
    PredicateKind, StorageIdentity, int, int,
] | None:
    """Return the exact semantic predicate proposed by one lowering step."""

    if type(condition) is SyntheticStackValueEqualsCondition:
        return (
            PredicateKind.EQ,
            StorageIdentity(StorageIdentityKind.STACK, condition.stack_stkoff),
            condition.stack_size,
            condition.value,
        )
    if type(condition) is SyntheticCounterBoundCondition:
        if (condition.counter_stkoff is None) == (condition.counter_reg is None):
            return None
        storage = StorageIdentity(
            StorageIdentityKind.STACK
            if condition.counter_stkoff is not None
            else StorageIdentityKind.REGISTER,
            condition.counter_stkoff
            if condition.counter_stkoff is not None
            else condition.counter_reg,
        )
        return (
            PredicateKind.SLT if condition.signed else PredicateKind.ULT,
            storage,
            condition.counter_size,
            condition.bound,
        )
    if type(condition) is SyntheticRegisterNonzeroCondition:
        return (
            PredicateKind.NE,
            StorageIdentity(
                StorageIdentityKind.REGISTER, condition.predicate_reg,
            ),
            condition.predicate_size,
            0,
        )
    return None


def _mint_observed_lowered_conditional_topology_occurrences(
    *,
    blocks: Mapping[int, BlockSnapshot],
    serial_by_ref: Mapping[object, int],
    projected_inventory: model.SemanticGraphInventory | None,
    realization: model.ProjectedRouteRealization | None,
    patch_facts: tuple[model.PatchStepEvidencePayload, ...],
    plan: PatchPlan,
) -> tuple[model.ObservedLoweredConditionalTopologyOccurrence, ...]:
    """Validate auxiliary conditional lowerings once at the transaction edge."""

    if projected_inventory is None:
        return ()
    model.validate_semantic_graph_inventory(projected_inventory)
    if (
        projected_inventory.phase
        is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    ):
        raise ValueError(
            "observed lowered conditional occurrence requires projected inventory",
        )
    if type(plan) is not PatchPlan:
        raise TypeError("observed lowered conditional occurrence requires PatchPlan")
    represented_steps = (
        {row.plan_step_index for row in realization.rows}
        if type(realization) is model.ProjectedRouteRealization
        else set()
    )
    projected_rows = {row.serial: row for row in projected_inventory.blocks}
    projected_topology = {
        (item.owner_serial, item.peer_serial)
        for item in projected_inventory.topology
        if item.kind is model.TopologyIncidenceKind.SUCCESSOR
    }
    subjects_by_ref: dict[object, tuple[str, ...]] = {}
    for subject in projected_inventory.subjects:
        if (
            subject.block_ref is not None
            and subject.role in model.TOPOLOGY_SUBJECT_ROLES
        ):
            subjects_by_ref.setdefault(subject.block_ref, ())
            subjects_by_ref[subject.block_ref] = tuple(sorted({
                *subjects_by_ref[subject.block_ref], subject.subject_id,
            }))

    def reciprocal(rows, left: int, right: int) -> bool:
        return bool(
            left in rows
            and right in rows
            and right in rows[left].successor_serials
            and left in rows[right].predecessor_serials
        )

    def observed_reciprocal(left: int, right: int) -> bool:
        return bool(
            left in blocks
            and right in blocks
            and right in blocks[left].succs
            and left in blocks[right].preds
        )

    def projected_pairs(left_ref: object, right_ref: object):
        left = projected_inventory.serial_by_ref.get(left_ref)
        right = projected_inventory.serial_by_ref.get(right_ref)
        if (
            left is None
            or right is None
            or (left, right) not in projected_topology
        ):
            return ()
        left_ids = subjects_by_ref.get(left_ref, ())
        right_ids = subjects_by_ref.get(right_ref, ())
        row = projected_rows.get(left)
        if not left_ids or not right_ids or row is None or row.anchor_ea is None:
            return ()
        return tuple(sorted({
            model.TopologyEdgeRelation(
                model.SemanticEdgeRole.DIRECT, source, target, row.anchor_ea,
            )
            for source in left_ids for target in right_ids
        } | {
            model.TopologyEdgeRelation(
                model.SemanticEdgeRole.DIRECT, target, source, row.anchor_ea,
            )
            for source in left_ids for target in right_ids
        }, key=lambda item: (
            item.source_subject_id,
            item.target_subject_id,
            item.native_edge_anchor_ea,
        )))

    results: list[model.ObservedLoweredConditionalTopologyOccurrence] = []
    for step_index, step in enumerate(plan.steps):
        if (
            type(step) is not PatchLowerConditionalStateTransition
            or step_index in represented_steps
        ):
            continue
        descriptor = canonical_patch_step_descriptor(plan, step_index)
        matching_facts = tuple(
            fact for fact in patch_facts
            if fact.plan_id == plan.plan_id
            and fact.step_index == step_index
            and fact.step_type == "PatchLowerConditionalStateTransition"
            and fact.owner_ref == step.source_serial
            and fact.step_digest == descriptor.step_digest
        )
        if len(matching_facts) != 1:
            continue
        signature = _lowered_condition_signature(step.condition_operand)
        if signature is None:
            continue
        source_ref = step.source_serial
        false_ref = step.false_target_serial
        true_ref = step.true_target_serial
        projected_serials = tuple(
            projected_inventory.serial_by_ref.get(ref)
            for ref in (source_ref, false_ref, true_ref)
        )
        if any(serial is None for serial in projected_serials):
            continue
        projected_source, projected_false, projected_true = projected_serials
        projected_row = projected_rows.get(projected_source)
        if (
            projected_row is None
            or projected_row.block_kind is not BlockKind.TWO_WAY
            or projected_row.successor_serials
            != (projected_false, projected_true)
            or not reciprocal(projected_rows, projected_source, projected_false)
            or not reciprocal(projected_rows, projected_source, projected_true)
            or not projected_row.instruction_observations
        ):
            continue
        projected_predicate = (
            projected_row.instruction_observations[-1].predicate_observation
        )
        if (
            projected_predicate is None
            or (
                projected_predicate.predicate_kind,
                projected_predicate.storage_identity,
                projected_predicate.width,
                projected_predicate.compare_constant,
            ) != signature
            or projected_predicate.explicit_target_serial != projected_true
        ):
            continue
        observed_serials = tuple(
            serial_by_ref.get(ref) for ref in (source_ref, false_ref, true_ref)
        )
        if any(serial is None for serial in observed_serials):
            continue
        observed_source, observed_false, observed_true = observed_serials
        live = blocks.get(observed_source)
        if (
            live is None
            or live.kind is not BlockKind.TWO_WAY
            or len(live.succs) != 2
            or not live.insn_snapshots
            or live.succs[1] != observed_true
            or not observed_reciprocal(observed_source, observed_true)
        ):
            continue
        live_row = producer_api.observe_inventory_block(
            live,
            owner_ref=source_ref,
            owner_anchor_ea=projected_row.anchor_ea,
        )
        live_predicate = live_row.instruction_observations[-1].predicate_observation
        if (
            live_predicate is None
            or (
                live_predicate.predicate_kind,
                live_predicate.storage_identity,
                live_predicate.width,
                live_predicate.compare_constant,
            ) != signature
            or live_predicate.explicit_target_serial != observed_true
        ):
            continue
        if live.succs[0] == observed_false:
            if not observed_reciprocal(observed_source, observed_false):
                continue
        else:
            helper_serial = live.succs[0]
            helper = blocks.get(helper_serial)
            if (
                helper_serial != observed_source + 1
                or helper is None
                or helper_serial in serial_by_ref.values()
                or helper.preds != (observed_source,)
                or helper.succs != (observed_false,)
                or not _is_exact_unconditional_goto_to(helper, observed_false)
                or helper.insn_snapshots[-1].opcode < 0
                or helper.insn_snapshots[-1].raw_opcode
                != helper.insn_snapshots[-1].opcode
                or not observed_reciprocal(observed_source, helper_serial)
                or not observed_reciprocal(helper_serial, observed_false)
            ):
                continue
        pairs = tuple(sorted({
            *projected_pairs(source_ref, false_ref),
            *projected_pairs(source_ref, true_ref),
        }, key=lambda item: (
            item.source_subject_id,
            item.target_subject_id,
            item.native_edge_anchor_ea,
        )))
        if not pairs:
            continue
        results.append(
            authority_bind.mint_observed_lowered_conditional_topology_occurrence(
                patch_fact=matching_facts[0],
                source_ref=source_ref,
                false_target_ref=false_ref,
                true_target_ref=true_ref,
                normalized_pairs=pairs,
            ),
        )
    pair_domains: set[frozenset[str]] = set()
    for occurrence in results:
        occurrence_domains = {
            frozenset((pair.source_subject_id, pair.target_subject_id))
            for pair in occurrence.normalized_pairs
        }
        if occurrence_domains & pair_domains:
            raise ValueError(
                "lowered conditional topology occurrences overlap",
            )
        pair_domains.update(occurrence_domains)
    return tuple(sorted(results, key=lambda item: item.occurrence_id))


def _resolve_observed_logical_endpoint_occurrences(
    *,
    blocks: Mapping[int, BlockSnapshot],
    plan: PatchPlan,
    serial_by_ref: Mapping[object, int],
    projected_inventory: model.SemanticGraphInventory,
) -> tuple[model.ObservedLogicalEndpointOccurrence, ...]:
    """Bind moved logical exits from one exact projected transaction row."""
    model.validate_semantic_graph_inventory(projected_inventory)
    if (
        projected_inventory.phase
        is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    ):
        raise ValueError("logical endpoint reference must be projected preflight")
    projected_row_by_ref = {
        row.block_ref: row
        for row in projected_inventory.blocks
        if type(row.block_ref) is LogicalBlockRef
    }
    projected_ref_by_serial = {
        row.serial: row.block_ref
        for row in projected_inventory.blocks
        if row.block_ref is not None
    }
    observed_ref_by_serial = {
        serial: ref for ref, serial in serial_by_ref.items()
    }
    used_serials = set(serial_by_ref.values())
    candidates = tuple(
        block
        for serial, block in sorted(blocks.items())
        if serial not in used_serials
        and producer_api.is_exact_logical_function_exit(
            block,
            next(iter(projected_row_by_ref), None),
        )
    )
    eligible: list[model.ObservedLogicalEndpointOccurrence] = []
    for logical_ref, projected_row in projected_row_by_ref.items():
        if logical_ref in serial_by_ref:
            continue
        expected_predecessor_refs = tuple(
            projected_ref_by_serial.get(serial)
            for serial in projected_row.predecessor_serials
        )
        if (
            not expected_predecessor_refs
            or any(ref is None for ref in expected_predecessor_refs)
        ):
            continue
        matching_steps = tuple(
            (step, owner_ref)
            for step in plan.steps
            for owner_ref, target_ref in (
                (step.from_serial, step.new_target)
                if type(step) is PatchRedirectGoto
                else (step.block_serial, step.goto_target)
                if type(step) is PatchConvertToGoto
                else (None, None)
            ,)
            if target_ref == logical_ref
        )
        if len(matching_steps) != 1:
            continue
        _step, owner_ref = matching_steps[0]
        owner_serial = serial_by_ref.get(owner_ref)
        if (
            owner_serial is None
            or owner_ref not in expected_predecessor_refs
        ):
            continue
        owner_block = blocks.get(owner_serial)
        if owner_block is None:
            continue
        for candidate in candidates:
            if not _is_exact_unconditional_goto_to(
                owner_block,
                candidate.serial,
            ):
                continue
            if not candidate.preds or any(
                (predecessor := blocks.get(serial)) is None
                or candidate.serial not in predecessor.succs
                for serial in candidate.preds
            ):
                continue
            if set(candidate.preds) != {
                serial
                for serial, predecessor in blocks.items()
                if candidate.serial in predecessor.succs
            }:
                continue
            observed_predecessor_refs = tuple(
                observed_ref_by_serial.get(serial)
                for serial in candidate.preds
            )
            if (
                any(ref is None for ref in observed_predecessor_refs)
                or set(observed_predecessor_refs)
                != set(expected_predecessor_refs)
            ):
                continue
            eligible.append(authority_bind._mint_observed_logical_endpoint_occurrence(
                logical_ref=logical_ref,
                projected_serial=projected_row.serial,
                observed_serial=candidate.serial,
                owner_ref=owner_ref,
                predecessor_refs=tuple(expected_predecessor_refs),
            ))
    by_ref = {
        ref: tuple(item for item in eligible if item.logical_ref == ref)
        for ref in projected_row_by_ref
    }
    by_serial = {
        block.serial: tuple(
            item for item in eligible if item.observed_serial == block.serial
        )
        for block in candidates
    }
    return tuple(sorted(
        (
            item
            for item in eligible
            if len(by_ref[item.logical_ref]) == 1
            and len(by_serial[item.observed_serial]) == 1
        ),
        key=lambda item: (item.observed_serial, item.occurrence_id),
    ))


def _resolve_observed_native_entry_tails(
    *,
    blocks: Mapping[int, BlockSnapshot],
    proposal: model.ProposedUnflattenContract,
    plan: PatchPlan,
    serial_by_ref: Mapping[object, int],
    function_ea: int,
) -> _CandidateIdentityResolution:
    """Prebind only mutual-unique observed native rows with one owned tail."""
    result = dict(serial_by_ref)
    catalog = tuple(proposal.source_identity_catalog.blocks)
    used_serials = set(result.values())
    candidates: list[tuple[int, int, tuple[int, ...]]] = []
    for serial, block in blocks.items():
        if serial in used_serials:
            continue
        try:
            origins = producer_api.native_instruction_origins(block)
        except ValueError:
            continue
        anchor = block.native_start_ea if block.native_start_ea is not None else block.start_ea
        if type(anchor) is int and origins:
            candidates.append((int(serial), int(anchor), tuple(origins)))
    eligible: list[tuple[object, int, int]] = []
    for witness in catalog:
        if witness.block_ref in result or type(witness.block_ref) is not NativeBlockRef:
            continue
        matching_steps = tuple(
            step
            for step in plan.steps
            if (
                type(step) is PatchRedirectGoto
                and step.from_serial == witness.block_ref
            )
            or (
                type(step) is PatchConvertToGoto
                and step.block_serial == witness.block_ref
            )
        )
        if len(matching_steps) != 1:
            continue
        for serial, anchor, origins in candidates:
            if anchor != witness.anchor_ea:
                continue
            if function_ea in witness.native_instruction_eas:
                continue
            if origins != tuple(sorted((*witness.native_instruction_eas, function_ea))):
                continue
            trial = {**result, witness.block_ref: serial}
            tail = _observed_native_identity_origins(
                blocks[serial], owner_ref=witness.block_ref, serial_by_ref=trial,
                plan=plan, phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
                function_ea=function_ea,
            )
            if tail == function_ea:
                eligible.append((witness.block_ref, serial, tail))
    by_ref = {ref: tuple(item for item in eligible if item[0] == ref)
              for ref, _serial, _tail in eligible}
    by_serial = {serial: tuple(item for item in eligible if item[1] == serial)
                 for _ref, serial, _tail in eligible}
    accepted = tuple(
        item for item in eligible
        if len(by_ref[item[0]]) == 1 and len(by_serial[item[1]]) == 1
    )
    return _CandidateIdentityResolution(
        tuple(sorted(((ref, serial) for ref, serial, _tail in accepted), key=lambda item: item[1])),
        tuple(sorted(((serial, tail) for _ref, serial, tail in accepted))),
    )


from d810.transforms.unflatten_authority.ids import (
    _claim_factory,
    _subject_factory,
    authority_id,
    bound_unflatten_binding_id,
    content_id,
    semantic_graph_fingerprint,
    semantic_graph_inventory_digest,
    projected_authority_id,
)

from .model import (
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)

logger = getLogger(__name__)

from .proposal import (
    MetadataKeyTypeError,
    PlanRouteResult,
    ProposalAccepted,
    ProposalRejected,
    RejectedPlanRoute,
    TypedProposalRoute,
    reserved_metadata_keys,
    validate_proposal,
)


@dataclass(frozen=True, slots=True)
class TimedUnflattenAuthorityResult:
    """Compatibility envelope for owner integrations needing phase timings."""

    result: (
        model.UnflattenAuthorityNotApplicable
        | model.UnflattenAuthorityPreparationAccepted
        | model.UnflattenAuthorityPreparationRejected
        | model.UnflattenAuthorityVerdict
    )
    timings: PhaseTimings

    def __post_init__(self) -> None:
        if type(self.result) not in (
            model.UnflattenAuthorityNotApplicable,
            model.UnflattenAuthorityPreparationAccepted,
            model.UnflattenAuthorityPreparationRejected,
            model.UnflattenAuthorityVerdict,
        ):
            raise TypeError("timed result is not a closed authority result")
        if type(self.timings) is not PhaseTimings:
            raise TypeError("timings must be PhaseTimings")


@dataclass(slots=True)
class _AuthorityTimingRecorder:
    inventory_ms: float | None = None
    binding_ms: float | None = None
    evaluation_ms: float | None = None


def _legacy_effective_gate_comparison_facts(raw: GenericEffectfulGateFacts) -> GenericEffectfulGateFacts:
    """Provide bind's legacy comparison DTO without serial-set authority.

    The binder independently verifies this optimistic compatibility projection
    against sealed projected site dispositions.  A new unclassified loss makes
    that verification reject; no transaction gate consumes this DTO.
    """
    if type(raw) is not GenericEffectfulGateFacts:
        raise TypeError("legacy effective comparison requires raw effect facts")
    return GenericEffectfulGateFacts(
        True,
        raw.pre_effectful_block_serials,
        raw.pre_effectful_block_serials,
        frozenset(),
        raw.reason,
    )


def _elapsed_ms(start_ns: int, end_ns: int) -> float:
    return (end_ns - start_ns) / 1_000_000.0


def _subject(kind, role, locator):
    owner = getattr(locator, "block_ref", None)
    if owner is None:
        owner = getattr(locator, "owner_ref", None)
    if owner is None:
        owner = getattr(locator, "source_ref", None)
    if owner is None:
        owner = getattr(locator, "entry_ref", None)
    anchor = getattr(locator, "anchor_ea", None)
    if anchor is None:
        anchor = getattr(locator, "owner_anchor_ea", None)
    if anchor is None:
        anchor = getattr(locator, "source_anchor_ea", None)
    if anchor is None:
        anchor = getattr(locator, "entry_anchor_ea", None)
    return _subject_factory(
        model.SemanticSubjectRef,
        kind=kind,
        role=role,
        block_ref=owner,
        anchor_ea=anchor,
        locator=locator,
    )


def _unavailable_candidate_fingerprint(plan_id: str) -> str:
    return authority_id(("candidate-fingerprint-unavailable", plan_id))


def _live_binding_failed_verdict(
    detail: str | None = None,
) -> model.UnflattenAuthorityVerdict:
    """Return a total rejection without dereferencing an untrusted carrier."""
    return model.UnflattenAuthorityVerdict(
        False,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        None,
        None,
        None,
        _unavailable_candidate_fingerprint("observed-live-binding"),
        None,
        (),
        rejection_detail=detail,
    )


def _record_route_authority_rebind(
    evidence: CanonicalSemanticEvidence,
    *,
    phase: model.UnflattenAuthorityPhase,
) -> RouteRebindVerification:
    """Rebind one bundle at the producer/transaction seam and record the outcome.

    The seam's substantive check -- that every producer reference names this
    bundle's own proof record -- can only run while the producer's arena is
    open, and whether it is depends on which producer path built the bundle
    (``runtime_authority`` module docstring names both).  Neither answer is a
    fault, but "the check did not run" must not be invisible: the outcome is
    stored on the session by the rebind, stated here, and **returned** so that
    it can ride the phase's result record.  The session's copy dies with the
    session, so the returned value is the one that survives into a receipt.
    """

    rebind = rebind_route_evidence(evidence)
    if rebind.records_verified:
        # Deliberately unguarded.  ``logger.debug_on`` is a ``LevelFlag`` whose
        # cache refreshes on a *config version* counter, not on a level change,
        # so evaluating it here -- once per transaction, i.e. early and often --
        # freezes the flag for this module's logger for the rest of the process
        # and silently disables every later ``debug_on``-guarded diagnostic,
        # including under ``caplog.set_level``.  The suite caught exactly that.
        # ``logger.debug`` with %-style arguments already short-circuits, and
        # these arguments are three attribute reads and a ``len``.
        logger.debug(
            "unflatten authority %s route rebind: %s (%d route proofs)",
            phase.value, rebind.verification.value, len(rebind.binding.proof_refs),
        )
        return rebind.verification
    logger.info(
        "unflatten authority %s route rebind could not verify producer records: "
        "%s (%d route proofs)",
        phase.value, rebind.verification.value, len(rebind.binding.proof_refs),
    )
    return rebind.verification


def _projected_route_authority_rebind_failure(
    stage: str,
    error: TypeError | ValueError,
    *,
    proposal,
) -> "UnflattenAuthorityPreparationRejected":
    """Report a projected seam refusal at its own stage, with its own fingerprint.

    The observed side already had stage-specific provenance; the projected side
    did not, because its seam sat inside the preparation's single several-hundred
    line ``try``.  A reader who saw ``PROJECTED_BINDING_FAILED`` with the plan's
    fingerprint had no way to tell a route-authority rebind refusal from any
    other preparation failure.
    """

    message = str(error)
    if len(message) > 512:
        message = f"{message[:509]}..."
    logger.warning(
        "unflatten authority projected live binding rejected stage=%s %s: %s",
        stage, type(error).__name__, message,
    )
    verdict = model.UnflattenAuthorityVerdict(
        False,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        authority_id(proposal),
        None,
        None,
        _unavailable_candidate_fingerprint("projected-route-authority-rebind"),
        None,
        (),
        rejection_detail=stage,
    )
    return UnflattenAuthorityPreparationRejected(verdict)


def _observed_live_binding_failure(
    stage: str,
    error: TypeError | ValueError | AttributeError,
    *,
    authority_id_value: str | None = None,
    binding_id_value: str | None = None,
    candidate_fingerprint: str | None = None,
    route_authority_verification: RouteRebindVerification | None = None,
) -> model.UnflattenAuthorityVerdict:
    """Log a bounded stage-specific live binding rejection."""
    message = str(error)
    if len(message) > 512:
        message = f"{message[:509]}..."
    logger.warning(
        "observed unflatten authority live binding failed: stage=%s cause=%s: %s",
        stage,
        type(error).__name__,
        message,
    )
    # A live-binding rejection precedes every subject-keyed obligation, so it
    # can carry none.  Name the stage and cause instead of rejecting silently.
    detail = f"stage={stage} cause={type(error).__name__}: {message}"
    if (
        authority_id_value is None
        and binding_id_value is None
        and candidate_fingerprint is None
    ):
        return _live_binding_failed_verdict(detail)
    return model.UnflattenAuthorityVerdict(
        False,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        authority_id_value,
        binding_id_value,
        None,
        candidate_fingerprint or _unavailable_candidate_fingerprint("observed-live-binding"),
        None,
        (),
        rejection_detail=detail,
        _route_authority_verification=route_authority_verification,
    )


def _claim_subjects(claim):
    if type(claim) is model.RetiredDispatcherInfrastructureClaim:
        return (claim.infrastructure_subject, claim.corridor_subject, *claim.member_subjects)
    if type(claim) is model.DetachedDeadHandlerComponentClaim:
        return (claim.dispatcher_subject, *claim.dead_handler_subjects,
                *claim.retained_handler_subjects, *claim.component_subjects)
    if type(claim) is model.EquivalentSemanticRouteClaim:
        return (claim.retired_route_subject, claim.replacement_route_subject, claim.source_subject, *claim.destination_subjects, *claim.dag_endpoint_subjects)
    if type(claim) is model.ExactInfeasibleEffectClaim:
        return (claim.effect_subject, claim.source_subject, claim.predicate_subject, claim.selected_target_subject, claim.discarded_effect_subject)
    if type(claim) is model.LocalAliasEffectScalarizationClaim:
        return (claim.owner_subject,)
    if type(claim) is model.TerminalCycleBreakClaim:
        return (claim.cycle_subject, claim.cleanup_source_subject, claim.terminal_subject)
    raise TypeError("unsupported closed claim")


def _selected_route_subject_refs(proposal) -> set[object]:
    """Project the complete selected canonical route witness into CFG refs.

    Route claims name their semantic source and destinations, while the
    selected decision-DAG proof owns the comparison, alias, and namespace
    bridge members that connect them.  Patch lineage must consume that same
    typed witness closure; reconstructing it from the planned redirects would
    recreate the proof-authority split this package exists to remove.
    """

    selected_proof_ids = {
        proof_id
        for claim in proposal.claims
        if type(claim) is model.EquivalentSemanticRouteClaim
        for proof_id in claim.route_proof_ids
    }
    refs = {
        subject.block_ref
        for claim in proposal.claims
        for subject in _claim_subjects(claim)
        if subject.block_ref is not None
    }
    selected_proofs = tuple(
        proof
        for proof in proposal.route_evidence.route_proofs
        if proof.proof_id in selected_proof_ids
    )
    if {proof.proof_id for proof in selected_proofs} != selected_proof_ids:
        raise ValueError("selected route claim is absent from canonical evidence")

    native_refs_by_identity: dict[object, set[NativeBlockRef]] = {}
    for row in proposal.source_identity_catalog.blocks:
        if type(row.block_ref) is NativeBlockRef:
            native_refs_by_identity.setdefault(
                row.block_ref.identity, set(),
            ).add(row.block_ref)

    dag_points: list[SemanticCorridorPoint] = []
    for proof in selected_proofs:
        if proof.source_owner_identity is not None:
            dag_points.append(SemanticCorridorPoint(
                proof.source_owner_identity,
                proof.source_owner_anchor_ea,
            ))
        if proof.bootstrap is not None:
            # A bootstrap entry is a view over the selected transition proof,
            # not a second allowance.  Its stable corridor is nevertheless
            # part of that proof's physical route closure and may own the
            # entry-to-dispatcher redirect applied by the transaction.
            dag_points.extend((
                proof.bootstrap.entry,
                proof.bootstrap.source,
                proof.bootstrap.owner,
                proof.bootstrap.dispatcher,
                *proof.bootstrap.corridor,
            ))
        if proof.state_dag is None:
            continue
        witness = proof.state_dag.witness
        dag_points.extend((witness.entry, *witness.path))
        for comparison in witness.comparisons:
            dag_points.append(comparison.node)
            dag_points.extend(
                endpoint
                for endpoint in (
                    comparison.true_target, comparison.false_target,
                )
                if type(endpoint) is SemanticCorridorPoint
            )
        for source_point, target_point in witness.aliases:
            dag_points.extend((source_point, target_point))
        dag_points.extend(bridge.node for bridge in witness.bridges)

    for point in dag_points:
        matches = native_refs_by_identity.get(point.identity, set())
        if len(matches) != 1:
            raise ValueError(
                "selected canonical route member lacks one exact source reference"
            )
        refs.update(matches)
    return refs


def _source_entry_dispatcher_frontier_refs(
    source_inventory: model.SemanticGraphInventory,
    proposal: model.ProposedUnflattenContract,
) -> set[object]:
    """Classify exact entry-side predecessors of the dispatcher.

    The dispatcher is a traversal barrier.  Reachability starts from the same
    physical entry plus selected semantic-route roots used by the canonical
    inventory, so entry lineage and effect/coverage classification cannot
    disagree about disconnected native route components.
    """

    model.validate_semantic_graph_inventory(source_inventory)
    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("entry frontier requires a closed unflatten proposal")
    serial_by_ref = source_inventory.serial_by_ref
    entry_serial = serial_by_ref.get(proposal.plan_inputs.source_entry_ref)
    dispatcher_serial = serial_by_ref.get(
        proposal.plan_inputs.dispatcher_entry_ref
    )
    if entry_serial is None or dispatcher_serial is None:
        raise ValueError("entry frontier coordinates are absent from source inventory")
    if int(entry_serial) != int(source_inventory.entry_serial):
        raise ValueError("proposal source entry differs from source inventory")
    blocks = {block.serial: block for block in source_inventory.blocks}
    roots = {int(entry_serial)}
    for claim in proposal.claims:
        if type(claim) is not model.EquivalentSemanticRouteClaim:
            continue
        route_source = serial_by_ref.get(claim.source_subject.block_ref)
        if route_source is None:
            raise ValueError("selected route source is absent from source inventory")
        roots.add(int(route_source))
    reachable_before_dispatch: set[int] = set()
    pending = list(sorted(roots, reverse=True))
    while pending:
        serial = pending.pop()
        if serial == int(dispatcher_serial) or serial in reachable_before_dispatch:
            continue
        block = blocks.get(serial)
        if block is None:
            raise ValueError("entry frontier traversal left source inventory")
        reachable_before_dispatch.add(serial)
        pending.extend(
            successor
            for successor in block.successor_serials
            if successor != int(dispatcher_serial)
        )
    reachable_frontier = {
        block.block_ref
        for serial in reachable_before_dispatch
        if (block := blocks[serial]).block_ref is not None
        and int(dispatcher_serial) in block.successor_serials
    }
    additional_native_roots = {
        block.block_ref
        for block in source_inventory.blocks
        if type(block.block_ref) is NativeBlockRef
        and not block.predecessor_serials
        and int(dispatcher_serial) in block.successor_serials
    }
    return reachable_frontier | additional_native_roots


def _is_exact_source_logical_exit(
    blocks: Mapping[int, BlockSnapshot],
    serial: int,
    ref: object,
) -> bool:
    """Bind one source-owned logical sink and its reciprocal incoming edge."""

    block = blocks.get(int(serial))
    return bool(
        type(ref) is LogicalBlockRef
        and block is not None
        and producer_api.is_exact_logical_function_exit(block, ref)
        and block.preds
        and all(
            (predecessor := blocks.get(int(pred))) is not None
            and int(serial) in tuple(int(item) for item in predecessor.succs)
            for pred in block.preds
        )
    )


def _catalog_serials(source: FlowGraph, proposal, plan: PatchPlan, *, blocks=None) -> dict[object, int]:
    block_map = source.blocks if blocks is None else blocks
    rows = tuple(plan.source_coordinates)
    if len(rows) != len(block_map):
        raise ValueError("plan source coordinates do not cover the source graph")
    by_ref = {ref: int(serial) for ref, serial in rows}
    expected = {item.block_ref for item in proposal.source_identity_catalog.blocks}
    if not expected <= set(by_ref) or set(by_ref.values()) != set(block_map):
        raise ValueError("plan source coordinates differ from the source catalog")
    if any(serial not in block_map for serial in by_ref.values()):
        raise ValueError("plan source coordinate points outside the source graph")
    selected_route_proof_ids = {
        proof_id
        for claim in proposal.claims
        if type(claim) is model.EquivalentSemanticRouteClaim
        for proof_id in claim.route_proof_ids
    }
    selected_logical_endpoint_serials = {
        int(endpoint.serial)
        for proof in proposal.route_evidence.route_proofs
        if proof.proof_id in selected_route_proof_ids and proof.state_dag is not None
        for comparison in proof.state_dag.witness.comparisons
        for endpoint in (comparison.true_target, comparison.false_target)
        if type(endpoint) is SemanticLogicalDagEndpoint
    }
    terminal_logical_refs = {
        claim.terminal_subject.locator.block_ref: claim.terminal_subject.locator.serial
        for claim in proposal.claims
        if type(claim) is model.TerminalCycleBreakClaim
        and type(claim.terminal_subject.locator) is model.LogicalFunctionExitSubjectLocator
    }
    for ref, serial in by_ref.items():
        if ref in expected:
            continue
        source_logical_exit = (
            int(serial) not in selected_logical_endpoint_serials
            and _is_exact_source_logical_exit(block_map, serial, ref)
        )
        selected_logical_endpoint = (
            int(serial) in selected_logical_endpoint_serials
            and producer_api.is_exact_logical_function_exit(block_map[serial], ref)
        )
        selected_terminal_logical = (
            terminal_logical_refs.get(ref) == int(serial)
            and producer_api.is_exact_logical_function_exit(block_map[serial], ref)
        )
        if not source_logical_exit and not selected_logical_endpoint and not selected_terminal_logical and not producer_api.is_unowned_structural_logical_stop(
            block_map[serial], ref,
        ):
            raise ValueError("plan source coordinates contain an unowned non-structural reference")
    # Keep only a selected logical function-exit coordinate in addition to the
    # native source catalog.  It is intentionally anchorless but source route
    # binding consumes its owned row to compare session/token/version for the
    # exact typed DAG leaf.  An unrelated synthetic STOP stays ownerless.
    return {
        ref: serial
        for ref, serial in by_ref.items()
        if ref in expected
        or (
            int(serial) not in selected_logical_endpoint_serials
            and _is_exact_source_logical_exit(block_map, serial, ref)
        )
        or (
            int(serial) in selected_logical_endpoint_serials
            and producer_api.is_exact_logical_function_exit(block_map[serial], ref)
        ) or terminal_logical_refs.get(ref) == int(serial)
        and producer_api.is_exact_logical_function_exit(block_map[serial], ref)
    }


def _projected_plan_serials(plan: PatchPlan) -> dict[PlanBlockRef, int]:
    """Resolve planned block references in the immutable projection coordinate space."""

    if not plan.new_blocks:
        return {}
    source_coordinates = dict(plan.source_coordinates)
    source_stop = plan.relocation_map.source_stop
    stop_before = source_coordinates.get(source_stop) if source_stop is not None else None
    if stop_before is None and source_coordinates:
        stop_before = max(source_coordinates.values())
    if stop_before is None:
        return {}
    return {
        spec.block_id: int(stop_before) + offset
        for offset, spec in enumerate(plan.new_blocks)
    }


def _resolve_candidate_identities(
    graph: FlowGraph, proposal, *, blocks=None, plan: PatchPlan | None = None,
    planned_serials: Mapping[PlanBlockRef, int] | None = None,
    phase: model.UnflattenAuthorityPhase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    projected_reference_inventory: model.SemanticGraphInventory | None = None,
    source_inventory: model.SemanticGraphInventory | None = None,
    observed_patch_binding: ObservedPatchBinding | None = None,
) -> _CandidateIdentityResolution:
    result: dict[object, int] = {}
    block_values = graph.blocks if blocks is None else blocks
    catalog_by_ref = {
        witness.block_ref: witness
        for witness in proposal.source_identity_catalog.blocks
    }
    route_claims = getattr(proposal, "claims", ())
    route_evidence = getattr(proposal, "route_evidence", None)
    selected_route_proof_ids = {
        proof_id
        for claim in route_claims
        if type(claim) is model.EquivalentSemanticRouteClaim
        for proof_id in claim.route_proof_ids
    }
    selected_logical_endpoint_by_serial = {
        int(endpoint.serial): endpoint
        for proof in (() if route_evidence is None else route_evidence.route_proofs)
        if proof.proof_id in selected_route_proof_ids and proof.state_dag is not None
        for comparison in proof.state_dag.witness.comparisons
        for endpoint in (comparison.true_target, comparison.false_target)
        if type(endpoint) is SemanticLogicalDagEndpoint
    }
    terminal_logical_ref_by_serial = {
        claim.terminal_subject.locator.serial: claim.terminal_subject.locator.block_ref
        for claim in route_claims
        if type(claim) is model.TerminalCycleBreakClaim
        and type(claim.terminal_subject.locator) is model.LogicalFunctionExitSubjectLocator
    }
    sealed_source_ref_by_serial = {
        int(serial): ref
        for ref, serial in (() if plan is None else plan.source_coordinates)
        if ref in catalog_by_ref
        or (
            int(serial) not in selected_logical_endpoint_by_serial
            and _is_exact_source_logical_exit(block_values, int(serial), ref)
        )
        or (
            type(ref) is LogicalBlockRef
            and int(serial) in selected_logical_endpoint_by_serial
            and selected_logical_endpoint_by_serial[int(serial)].session_id == ref.session_id
            and selected_logical_endpoint_by_serial[int(serial)].proxy_token == ref.proxy_token
            and selected_logical_endpoint_by_serial[int(serial)].version == ref.version
        )
        or terminal_logical_ref_by_serial.get(int(serial)) == ref
    }
    if planned_serials is None:
        planned_serials = _projected_plan_serials(plan) if plan is not None else {}
    else:
        planned_serials = dict(planned_serials)
        if any(type(ref) is not PlanBlockRef or type(serial) is not int or serial < 0
               for ref, serial in planned_serials.items()):
            raise ValueError("observed helper coordinates must be exact PlanBlockRef rows")
    planned_serial_set = set(planned_serials.values())
    candidate_identities = []
    for block in block_values.values():
        if block.serial in planned_serial_set:
            continue
        sealed_ref = sealed_source_ref_by_serial.get(int(block.serial))
        if (
            type(sealed_ref) is LogicalBlockRef
            and producer_api.is_exact_logical_function_exit(block, sealed_ref)
        ):
            # A selected DAG function-exit is a transaction coordinate, not a
            # native source identity.  Preserve only its exact sealed serial;
            # unrelated instructionless STOP rows remain ownerless.
            result[sealed_ref] = int(block.serial)
            continue
        try:
            native_origins = producer_api.native_instruction_origins(block)
        except ValueError:
            # Backend-generated structural blocks have no native coordinate
            # and therefore cannot witness a source-catalog identity. They
            # remain ownerless inventory rows below.
            continue
        native_start_ea = getattr(block, "native_start_ea", None)
        if not native_origins and native_start_ea is None:
            sealed_ref = sealed_source_ref_by_serial.get(int(block.serial))
            witness = catalog_by_ref.get(sealed_ref)
            graph_start_ea = getattr(block, "start_ea", None)
            if (
                witness is not None
                and witness.native_instruction_eas == ()
                and type(graph_start_ea) is int
                and graph_start_ea == witness.anchor_ea
            ):
                # The plan's immutable source-coordinate occurrence is the
                # provenance for a retained instructionless source block. A
                # graph-local matching EA without this exact occurrence stays
                # ownerless.
                result[sealed_ref] = int(block.serial)
                continue
            # An instructionless backend-created block can choose a graph-local
            # start EA that happens to equal a source witness. Without either
            # a native instruction origin or an explicit native block anchor,
            # that coincidence is not source identity authority.
            continue
        candidate_identities.append((
            int(block.serial),
            native_start_ea
            if native_start_ea is not None
            else getattr(block, "start_ea", None),
            native_origins,
        ))
    candidate_identities = tuple(candidate_identities)
    witnesses_by_anchor: dict[int, list[object]] = {}
    candidates_by_anchor: dict[int, list[tuple[int, tuple[int, ...]]]] = {}
    for witness in proposal.source_identity_catalog.blocks:
        if witness.block_ref in result:
            # Exact plan-sealed occurrences are final. Reintroducing their
            # witness into generic anchor matching would let a competing block
            # overwrite transaction-owned source identity.
            continue
        witnesses_by_anchor.setdefault(witness.anchor_ea, []).append(witness)
    for serial, anchor_ea, native_instruction_eas in candidate_identities:
        if anchor_ea is not None:
            candidates_by_anchor.setdefault(int(anchor_ea), []).append(
                (serial, native_instruction_eas)
            )

    for anchor_ea, witnesses in witnesses_by_anchor.items():
        remaining_witnesses = list(witnesses)
        remaining_candidates = list(candidates_by_anchor.get(anchor_ea, ()))

        # Exact native origins disambiguate distinct physical blocks that share
        # an anchor.  Accept only mutual-unique pairs so this resolution stays
        # injective even when a backend duplicates one candidate identity.
        while remaining_witnesses and remaining_candidates:
            exact_by_witness = {
                witness.block_ref: tuple(
                    candidate
                    for candidate in remaining_candidates
                    if candidate[1] == witness.native_instruction_eas
                )
                for witness in remaining_witnesses
            }
            exact_by_candidate = {
                candidate[0]: tuple(
                    witness
                    for witness in remaining_witnesses
                    if candidate[1] == witness.native_instruction_eas
                )
                for candidate in remaining_candidates
            }
            pairs = tuple(
                (witness, matches[0])
                for witness in remaining_witnesses
                if len(matches := exact_by_witness[witness.block_ref]) == 1
                and len(exact_by_candidate[matches[0][0]]) == 1
            )
            if not pairs:
                break
            for witness, candidate in pairs:
                result[witness.block_ref] = int(candidate[0])
                remaining_witnesses.remove(witness)
                remaining_candidates.remove(candidate)

        # Observed folding may remove instructions from a surviving owner.
        # After exact identities have been consumed, only a final 1:1
        # remainder is strong enough to preserve that physical identity.
        if len(remaining_witnesses) == len(remaining_candidates) == 1:
            result[remaining_witnesses[0].block_ref] = int(
                remaining_candidates[0][0]
            )

    if len(set(result.values())) != len(result):
        raise ValueError("projected inventory has duplicate source identities")
    for ref, serial in planned_serials.items():
        if serial in block_values:
            if serial in result.values():
                raise ValueError("planned block coordinate overlaps a source identity")
            result[ref] = serial
    synthetic_tail_origin_by_serial: dict[int, int] = {}
    logical_endpoint_occurrences: tuple[
        model.ObservedLogicalEndpointOccurrence, ...
    ] = ()
    relocated_stop_tail_receipts: tuple[_ObservedRelocatedStopTailReceipt, ...] = ()
    if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY and plan is not None:
        resolution = _resolve_observed_native_entry_tails(
            blocks=block_values,
            proposal=proposal,
            plan=plan,
            serial_by_ref=result,
            function_ea=graph.func_ea,
        )
        result.update(dict(resolution.serial_bindings))
        synthetic_tail_origin_by_serial.update(
            resolution.synthetic_tail_origins,
        )
        for ref, serial in result.items():
            if type(ref) is not NativeBlockRef:
                continue
            if serial in synthetic_tail_origin_by_serial:
                continue
            tail_origin = _observed_native_identity_origins(
                block_values[serial],
                owner_ref=ref,
                serial_by_ref=result,
                plan=plan,
                phase=phase,
                function_ea=graph.func_ea,
            )
            if tail_origin is not None:
                synthetic_tail_origin_by_serial[serial] = tail_origin
        if projected_reference_inventory is not None:
            if source_inventory is None or observed_patch_binding is None:
                raise ValueError(
                    "relocated STOP normalization requires source inventory and observed binding"
                )
            relocated_stop_tail_receipts = (
                _mint_observed_relocated_stop_tail_receipts(
                    blocks=block_values,
                    plan=plan,
                    source_rows=source_inventory.blocks,
                    projected_rows=projected_reference_inventory.blocks,
                    observed_patch_binding=observed_patch_binding,
                    planned_serials=planned_serials,
                    function_ea=graph.func_ea,
                )
            )
            for receipt in relocated_stop_tail_receipts:
                _admit_relocated_stop_tail_owner(result, receipt)
            logical_endpoint_occurrences = (
                _resolve_observed_logical_endpoint_occurrences(
                    blocks=block_values,
                    plan=plan,
                    serial_by_ref=result,
                    projected_inventory=projected_reference_inventory,
                )
            )
            for occurrence in logical_endpoint_occurrences:
                if occurrence.observed_serial in result.values():
                    raise ValueError(
                        "observed logical endpoint overlaps another identity",
                    )
                result[occurrence.logical_ref] = occurrence.observed_serial
    return _CandidateIdentityResolution(
        tuple(sorted(result.items(), key=lambda item: (item[1], repr(item[0])))),
        tuple(sorted(synthetic_tail_origin_by_serial.items())),
        logical_endpoint_occurrences,
        relocated_stop_tail_receipts,
    )


def _projected_serials(
    graph: FlowGraph, proposal, *, blocks=None, plan: PatchPlan | None = None,
    planned_serials: Mapping[PlanBlockRef, int] | None = None,
    phase: model.UnflattenAuthorityPhase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    projected_reference_inventory: model.SemanticGraphInventory | None = None,
    source_inventory: model.SemanticGraphInventory | None = None,
    observed_patch_binding: ObservedPatchBinding | None = None,
) -> dict[object, int]:
    """Compatibility view over the closed candidate-identity resolution."""
    return dict(_resolve_candidate_identities(
        graph,
        proposal,
        blocks=blocks,
        plan=plan,
        planned_serials=planned_serials,
        phase=phase,
        projected_reference_inventory=projected_reference_inventory,
        source_inventory=source_inventory,
        observed_patch_binding=observed_patch_binding,
    ).serial_bindings)


def _block_subjects(proposal, serials, *, include_corridor=True):
    catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    subjects = []
    def add(role, ref):
        witness = catalog[ref]
        subjects.append(_subject(model.SemanticSubjectKind.BLOCK, role, model.BlockSubjectLocator(ref, witness.anchor_ea)))
    inputs = proposal.plan_inputs
    add(model.SemanticSubjectRole.SOURCE_ENTRY, inputs.source_entry_ref)
    add(model.SemanticSubjectRole.DISPATCHER_ENTRY, inputs.dispatcher_entry_ref)
    for ref in inputs.dispatcher_member_refs:
        add(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, ref)
    for handler in inputs.authoritative_handlers:
        subjects.append(_subject(model.SemanticSubjectKind.HANDLER, model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, model.HandlerSubjectLocator(handler.block_ref, handler.anchor_ea, handler.normalized_states)))
    if include_corridor:
        refs = inputs.dispatcher_member_refs
        subjects.append(_subject(model.SemanticSubjectKind.CORRIDOR, model.SemanticSubjectRole.DISPATCHER_CORRIDOR, model.CorridorSubjectLocator(
            content_id("unflatten.corridor.v1", refs), inputs.dispatcher_entry_ref,
            catalog[inputs.dispatcher_entry_ref].anchor_ea, refs,
            tuple(catalog[ref].anchor_ea for ref in refs),
        )))
    return subjects


def _inventory_subjects(
    proposal, source_serials, effects=(), terminals=(), plan=None,
    planned_helpers: Mapping[PlanBlockRef, int] | None = None,
):
    subjects = _block_subjects(
        proposal, source_serials,
        include_corridor=proposal.corridor_coverage_forecast is not None,
    )
    by_id = {subject.subject_id: subject for subject in subjects}
    # Every source-catalog identity has exactly one physical subject.  Do not
    # infer a helper role from the absence of another semantic view: helpers
    # are candidate-only PlanBlockRef materializations.
    for witness in proposal.source_identity_catalog.blocks:
        subject = _subject(
            model.SemanticSubjectKind.BLOCK,
            model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
            model.BlockSubjectLocator(witness.block_ref, witness.anchor_ea),
        )
        by_id[subject.subject_id] = subject
    # The fragment-wide value-flow subject is always present, even for an
    # exact-effect-only proposal.
    witness = proposal.use_def_witness
    value_flow = _subject(model.SemanticSubjectKind.VALUE_FLOW, model.SemanticSubjectRole.NON_STATE_VALUE_FLOW, model.ValueFlowSubjectLocator(
        witness.fragment_id, witness.state_identity, witness.redirect_owner_refs,
    ))
    by_id[value_flow.subject_id] = value_flow
    for claim in proposal.claims:
        for subject in _claim_subjects(claim):
            by_id[subject.subject_id] = subject
        if type(claim) is model.ExactInfeasibleEffectClaim:
            # The discarded effect owner participates in topology/accounting
            # separately from the selected target.  Project its claim-owned
            # coordinate as a block subject without minting a route subject
            # from route_proof_ids.
            effect = claim.discarded_effect_subject
            if type(effect.locator) is not model.EffectSubjectLocator:
                raise TypeError("exact-effect claim has an invalid discarded endpoint")
            endpoint = _subject(
                model.SemanticSubjectKind.BLOCK,
                model.SemanticSubjectRole.EXACT_EFFECT_DISCARDED_OWNER,
                model.BlockSubjectLocator(effect.locator.owner_ref, effect.locator.owner_anchor_ea),
            )
            by_id[endpoint.subject_id] = endpoint
    forecast = proposal.corridor_coverage_forecast
    if type(forecast) is model.DefaultGapInfeasibilityForecast:
        for exclusion in forecast.exclusions:
            for endpoint in (exclusion.default_entry, exclusion.residual):
                subject = _subject(
                    model.SemanticSubjectKind.BLOCK,
                    model.SemanticSubjectRole.DEFAULT_GAP_INFEASIBLE_RESIDUAL,
                    model.BlockSubjectLocator(
                        endpoint.block_ref, endpoint.anchor_ea,
                    ),
                )
                by_id[subject.subject_id] = subject
    # Logical function exits are source-owned coordinates, not native blocks
    # and not semantic terminal sites.  Inventory them through the existing
    # anchorless endpoint subject so binding can seal their exact
    # session/token/version while effect and terminal gates remain limited to
    # real semantic sites.
    claimed_logical_ref_by_serial = {
        subject.locator.serial: subject.locator.block_ref
        for subject in by_id.values()
        if type(subject.locator) is model.LogicalFunctionExitSubjectLocator
    }
    for ref, serial in source_serials.items():
        if type(ref) is not LogicalBlockRef:
            continue
        # A selected claim already owns this serial.  Do not let a plan-local
        # remint replace its sealed logical identity by minting a second
        # transaction-derived subject.
        if int(serial) in claimed_logical_ref_by_serial:
            continue
        locator = model.LogicalFunctionExitSubjectLocator(ref, int(serial))
        endpoint = _subject(
            model.SemanticSubjectKind.BLOCK,
            model.SemanticSubjectRole.SOURCE_LOGICAL_EXIT,
            locator,
        )
        by_id[endpoint.subject_id] = endpoint
    for item in effects:
        if item.owner_ref is None:
            continue
        locator = model.EffectSubjectLocator(
            item.owner_ref, item.owner_anchor_ea, item.instruction_ea, item.effect_kind,
        )
        subject = _subject(model.SemanticSubjectKind.EFFECT, model.SemanticSubjectRole.EFFECT_SITE, locator)
        by_id[subject.subject_id] = subject
    for item in terminals:
        if item.owner_ref is None:
            continue
        locator = model.TerminalSubjectLocator(
            item.owner_ref, item.owner_anchor_ea, item.terminal_kind, item.instruction_ea,
        )
        subject = _subject(model.SemanticSubjectKind.TERMINAL, model.SemanticSubjectRole.TERMINAL_SITE, locator)
        by_id[subject.subject_id] = subject
    if plan is not None:
        catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
        for step in plan.steps:
            if type(step) is not PatchScalarizeLocalAliasAccess:
                continue
            witness = catalog.get(step.block_serial)
            if witness is None:
                raise ValueError("local-alias step owner is absent from source catalog")
            owner = _subject(
                model.SemanticSubjectKind.BLOCK,
                model.SemanticSubjectRole.EFFECT_SITE,
                model.BlockSubjectLocator(step.block_serial, witness.anchor_ea),
            )
            by_id[owner.subject_id] = owner
    for ref, anchor in (planned_helpers or {}).items():
        helper = _subject(
            model.SemanticSubjectKind.BLOCK,
            model.SemanticSubjectRole.PLANNED_HELPER,
            model.BlockSubjectLocator(ref, anchor),
        )
        by_id[helper.subject_id] = helper
    return tuple(sorted(by_id.values(), key=lambda item: item.subject_id))


def _reachable_serials_from_blocks(blocks, entry_serial: int) -> frozenset[int]:
    if type(entry_serial) is not int or entry_serial < 0:
        raise ValueError("entry_serial must be an exact non-negative integer")
    if not blocks:
        if entry_serial != 0:
            raise ValueError("an empty graph must use entry_serial 0")
        return frozenset()
    if entry_serial not in blocks:
        raise ValueError("entry_serial is absent from graph blocks")
    seen: set[int] = set()
    pending = [entry_serial]
    while pending:
        serial = pending.pop()
        if serial in seen:
            continue
        block = blocks.get(serial)
        if block is None:
            raise ValueError("reachable graph successor is absent")
        seen.add(serial)
        pending.extend(sorted(block.succs, reverse=True))
    return frozenset(seen)


def _reachable_serials_from_semantic_roots(
    blocks,
    *,
    roots: tuple[int, ...] | list[int] | set[int],
    dispatcher_serial: int,
) -> frozenset[int]:
    """Close typed payload roots without reviving dispatcher infrastructure."""

    if type(dispatcher_serial) is not int or dispatcher_serial < 0:
        raise ValueError("dispatcher_serial must be an exact non-negative integer")
    if dispatcher_serial not in blocks:
        raise ValueError("dispatcher_serial is absent from graph blocks")
    if type(roots) not in (tuple, list, set) or any(
        type(root) is not int or root < 0 for root in roots
    ):
        raise TypeError("semantic roots must contain exact non-negative integers")
    reachable: set[int] = set()
    pending = list(sorted(set(roots), reverse=True))
    while pending:
        serial = pending.pop()
        if serial == dispatcher_serial or serial in reachable:
            continue
        block = blocks.get(serial)
        if block is None:
            raise ValueError("semantic root traversal left graph blocks")
        reachable.add(serial)
        pending.extend(
            successor
            for successor in sorted(block.succs, reverse=True)
            if successor != dispatcher_serial
        )
    return frozenset(reachable)


def _semantic_reachable_serials(
    blocks,
    *,
    entry_serial: int,
    serial_by_ref: Mapping[object, int],
    proposal: model.ProposedUnflattenContract,
    require_all_semantic_roots: bool = True,
) -> frozenset[int]:
    """Close reachability over physical entry and typed semantic roots.

    An indirect dispatcher may have no structural successor edges in the
    portable source graph even though the proposal has already bound its exact
    handler catalogue.  Those handlers are semantic roots for preservation;
    omitting them makes effects appear only after projection and splits the
    evidence model between route and effect gates.
    """

    physical_reachable = set(
        _reachable_serials_from_blocks(blocks, int(entry_serial))
    )
    candidate_semantic_loss_refs = frozenset()
    if not require_all_semantic_roots:
        candidate_semantic_loss_refs = (
            frozenset(
                subject.block_ref
                for claim in proposal.claims
                if type(claim) is model.DetachedDeadHandlerComponentClaim
                for subject in claim.dead_handler_subjects
            )
            | frozenset(
                claim.effect_subject.locator.owner_ref
                for claim in proposal.claims
                if type(claim) is model.ExactInfeasibleEffectClaim
            )
        )
        forecast = proposal.corridor_coverage_forecast
        if type(forecast) is model.DefaultGapInfeasibilityForecast:
            candidate_semantic_loss_refs |= frozenset(
                endpoint.block_ref
                for exclusion in forecast.exclusions
                for endpoint in (exclusion.default_entry, exclusion.residual)
            )
    semantic_roots: set[int] = set()
    for handler in proposal.plan_inputs.authoritative_handlers:
        # A typed semantic-loss claim proposes that this exact source block is
        # absent from the candidate closure.  Rooting a detached handler or an
        # exact-infeasible effect owner here would decide the opposite before
        # the transaction-owned binder can validate the claim.  Source
        # inventories still root every handler and route endpoint.
        if handler.block_ref in candidate_semantic_loss_refs:
            continue
        serial = serial_by_ref.get(handler.block_ref)
        if serial is None:
            if not require_all_semantic_roots:
                continue
            raise ValueError(
                "authoritative handler is absent from semantic inventory"
            )
        semantic_roots.add(int(serial))
    for claim in proposal.claims:
        if type(claim) is not model.EquivalentSemanticRouteClaim:
            continue
        route_subjects = (claim.source_subject, *claim.destination_subjects)
        for subject in route_subjects:
            if subject.block_ref in candidate_semantic_loss_refs:
                continue
            serial = serial_by_ref.get(subject.block_ref)
            if serial is None:
                if require_all_semantic_roots:
                    raise ValueError(
                        "canonical native route endpoint is absent from semantic inventory"
                    )
                continue
            semantic_roots.add(int(serial))
    dispatcher_serial = serial_by_ref.get(
        proposal.plan_inputs.dispatcher_entry_ref
    )
    if dispatcher_serial is None:
        raise ValueError("dispatcher entry is absent from semantic inventory")
    if require_all_semantic_roots:
        for root in sorted(semantic_roots):
            physical_reachable.update(
                _reachable_serials_from_blocks(blocks, root)
            )
    else:
        physical_reachable.update(
            _reachable_serials_from_semantic_roots(
                blocks,
                roots=semantic_roots,
                dispatcher_serial=int(dispatcher_serial),
            )
        )
    return frozenset(physical_reachable)


def _observed_native_identity_origins(
    block,
    *,
    owner_ref,
    serial_by_ref: Mapping[object, int],
    plan: PatchPlan,
    phase: model.UnflattenAuthorityPhase,
    function_ea: int,
) -> int | None:
    """Exclude one plan-authorized generated redirect from native identity.

    A live backend can append a synthetic GOTO to a retained native block and
    assign it a valid-looking fallback EA.  That transfer remains part of the
    observed instruction/topology inventory, but it is not a source-native
    instruction origin.  This exception is deliberately exact: one native
    owner, one exact ``PatchRedirectGoto`` or ``PatchConvertToGoto``, one tail
    GOTO, and its exact live target must all agree.  Every other additional
    origin stays in the row and is rejected by the normal native-identity
    invariant.  A ``PatchEdgeSplitCorridor`` may likewise redirect its exact
    ``via_pred`` to the first cloned helper; no other corridor member is
    authorized by this normalization.  Decline diagnostics are emitted only
    for matched candidates carrying a valid live tail origin.
    """
    if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        return None
    if type(owner_ref) is not NativeBlockRef:
        return None
    if type(function_ea) is not int or not 0 <= function_ea < 0xFFFFFFFFFFFFFFFF:
        raise ValueError("observed function entry EA must be exact")
    if owner_ref not in dict(plan.source_coordinates):
        return None

    def warn_decline(
        *,
        stage: str,
        reason: str,
        step: object | None = None,
        selected_target: object | None = None,
    ) -> None:
        """Log one bounded, anchored explanation for a matched live tail."""
        if not block.insn_snapshots:
            return
        tail = block.insn_snapshots[-1]
        tail_origin = tail.native_ea
        if type(tail_origin) is not int or not 0 <= tail_origin < 0xFFFFFFFFFFFFFFFF:
            tail_origin = tail.ea
        anchors = tuple(sorted(
            ea for ea in owner_ref.identity.exact_instruction_eas
            if type(ea) is int and 0 <= ea < 0xFFFFFFFFFFFFFFFF
        ))
        if not anchors or type(tail_origin) is not int or not 0 <= tail_origin < 0xFFFFFFFFFFFFFFFF:
            return
        serial = serial_by_ref.get(owner_ref)
        if type(serial) is not int or serial < 0:
            return
        target_serial = serial_by_ref.get(selected_target)
        shown_succs = tuple(block.succs[:8])
        succs = f"{shown_succs!r}" if len(block.succs) <= 8 else f"{shown_succs!r}+{len(block.succs) - 8}"
        tail_kind = tail.kind.value if type(tail.kind) is InsnKind else "unknown"
        block_kind = block.kind.value if type(block.kind) is BlockKind else "unknown"
        step_kind = type(step).__name__ if step is not None else "none"
        tail_native = tail.native_ea
        tail_native_text = (
            f"0x{tail_native:X}"
            if type(tail_native) is int and 0 <= tail_native < 0xFFFFFFFFFFFFFFFF
            else "none"
        )
        logger.warning(
            "observed generated-tail normalization declined "
            "blk%d@0x%X stage=%s reason=%s step=%s target=%s succs=%s "
            "block_kind=%s tail_kind=%s tail_opcode=%r raw_tail_opcode=%r "
            "tail_ea=0x%X tail_native_ea=%s",
            serial,
            anchors[0],
            stage,
            reason,
            step_kind,
            target_serial,
            succs,
            block_kind,
            tail_kind,
            tail.opcode,
            tail.raw_opcode,
            tail_origin,
            tail_native_text,
        )
    matching_steps = []
    for step in plan.steps:
        if type(step) is PatchRedirectGoto and step.from_serial == owner_ref:
            matching_steps.append((step, step.new_target))
        elif type(step) is PatchConvertToGoto and step.block_serial == owner_ref:
            matching_steps.append((step, step.goto_target))
        elif (
            type(step) is PatchEdgeSplitCorridor
            and step.via_pred == owner_ref
            and step.clone_block_ids
        ):
            matching_steps.append((step, step.clone_block_ids[0]))
    matching_steps = tuple(matching_steps)
    if len(matching_steps) != 1:
        if matching_steps:
            step, selected_target = matching_steps[0]
            warn_decline(
                stage="candidate",
                reason="multiple-matching-steps",
                step=step,
                selected_target=selected_target,
            )
        return None
    selected_step, selected_target = matching_steps[0]
    selected_serial = serial_by_ref.get(selected_target)
    if selected_serial is None:
        warn_decline(
            stage="target",
            reason="selected-target-unbound",
            step=selected_step,
            selected_target=selected_target,
        )
        return None
    if block.kind is not BlockKind.ONE_WAY:
        warn_decline(
            stage="topology", reason="block-is-not-one-way",
            step=selected_step, selected_target=selected_target,
        )
        return None
    if len(block.succs) != 1:
        warn_decline(
            stage="topology", reason="successor-count-mismatch",
            step=selected_step, selected_target=selected_target,
        )
        return None
    if block.succs[0] != selected_serial:
        warn_decline(
            stage="topology", reason="successor-target-mismatch",
            step=selected_step, selected_target=selected_target,
        )
        return None
    if not block.insn_snapshots:
        return None
    tail = block.insn_snapshots[-1]
    if (
        tail.kind is not InsnKind.GOTO
        or tail.control_transfer_kind is not ControlTransferKind.GOTO
        or not tail.is_unconditional_jump
        or tail.is_conditional_jump
        or tail.is_call
        or tail.call_kind is not None
        or tail.branch_predicate is not None
        or tail.predicate_kind is not None
        or tail.l is None
        or tail.l.kind is not OperandKind.BLOCK
        or tail.l.block_ref != block.succs[0]
        or tail.r is not None
        or tail.d is not None
    ):
        warn_decline(
            stage="tail", reason="tail-is-not-unconditional-goto",
            step=selected_step, selected_target=selected_target,
        )
        return None
    # Match producer_api's native-origin preference exactly: native EA when
    # valid, otherwise the backend row EA.  Do not normalize duplicate origins;
    # a duplicate foreign coordinate could belong to another live instruction.
    tail_origin = tail.native_ea
    if type(tail_origin) is not int or not 0 <= tail_origin < 0xFFFFFFFFFFFFFFFF:
        tail_origin = tail.ea
    if type(tail_origin) is not int or not 0 <= tail_origin < 0xFFFFFFFFFFFFFFFF:
        return None
    all_origins = []
    for instruction in block.insn_snapshots:
        origin = instruction.native_ea
        if type(origin) is not int or not 0 <= origin < 0xFFFFFFFFFFFFFFFF:
            origin = instruction.ea
        if type(origin) is not int or not 0 <= origin < 0xFFFFFFFFFFFFFFFF:
            warn_decline(
                stage="origin", reason="instruction-origin-unavailable",
                step=selected_step, selected_target=selected_target,
            )
            return None
        all_origins.append(origin)
    if all_origins.count(tail_origin) != 1:
        warn_decline(
            stage="origin", reason="tail-origin-not-unique",
            step=selected_step, selected_target=selected_target,
        )
        return None
    source_native_origins = {
        origin
        for source_ref, _serial in plan.source_coordinates
        if type(source_ref) is NativeBlockRef
        for origin in source_ref.identity.exact_instruction_eas
    }
    if tail_origin in source_native_origins and tail_origin != function_ea:
        warn_decline(
            stage="origin", reason="tail-origin-belongs-to-source",
            step=selected_step, selected_target=selected_target,
        )
        return None
    normalized_origins = tuple(sorted(set(all_origins) - {tail_origin}))
    if not set(normalized_origins) <= owner_ref.identity.exact_instruction_eas:
        warn_decline(
            stage="origin", reason="retained-origins-outside-owner",
            step=selected_step, selected_target=selected_target,
        )
        return None
    return tail_origin


def _bound_plan_helper_anchor_from_exact_origins(
    block: BlockSnapshot,
) -> int | None:
    """Derive a bound PlanBlockRef helper anchor from copied native rows."""
    origins = tuple(getattr(item, "native_ea", None) for item in block.insn_snapshots)
    if not origins or any(
        type(origin) is not int or not 0 <= origin < 0xFFFFFFFFFFFFFFFF
        for origin in origins
    ):
        return None
    return min(origins)


def _normalize_observed_plan_helper_allocation_origins(
    *,
    block: BlockSnapshot,
    observed: model.InventoryBlockObservation,
    projected: model.InventoryBlockObservation,
    owner_ref: PlanBlockRef,
    observed_patch_binding: ObservedPatchBinding,
    function_ea: int,
) -> model.InventoryBlockObservation:
    """Rebind exact helper allocation EAs to their projected native origins.

    ``create_standalone_block`` assigns ``mba.entry_ea`` to copied live rows.
    That address is an allocation coordinate, not native provenance.  Only the
    exact helper occurrence sealed by ``ObservedPatchBinding`` may reuse the
    already-validated projected row, and its instruction semantics must remain
    byte-for-byte equal after substituting those coordinates.
    """

    if type(block) is not BlockSnapshot:
        raise TypeError("observed helper block must be BlockSnapshot")
    if type(observed) is not model.InventoryBlockObservation:
        raise TypeError("observed helper row must be InventoryBlockObservation")
    if type(projected) is not model.InventoryBlockObservation:
        raise TypeError("projected helper row must be InventoryBlockObservation")
    if type(owner_ref) is not PlanBlockRef:
        raise TypeError("observed helper owner must be PlanBlockRef")
    validate_observed_patch_binding(observed_patch_binding)
    if (owner_ref, observed.serial) not in observed_patch_binding.bindings:
        raise ValueError("observed helper is absent from exact observed patch binding")
    if observed.block_ref != owner_ref or projected.block_ref != owner_ref:
        raise ValueError("observed/projected helper rows differ from exact helper")
    if projected.anchor_ea != observed.anchor_ea:
        raise ValueError("observed helper anchor differs from projected helper anchor")
    if (
        observed.block_kind is not projected.block_kind
        or len(observed.successor_serials) != len(projected.successor_serials)
    ):
        raise ValueError("observed helper topology shape differs from projected helper")
    if len(projected.instruction_observations) != len(
        observed.instruction_observations
    ):
        raise ValueError("observed helper body differs from projected helper body")
    raw_origins = tuple(
        row.native_ea
        if type(row.native_ea) is int and 0 <= row.native_ea < 0xFFFFFFFFFFFFFFFF
        else row.ea
        for row in block.insn_snapshots
    )
    collapsed_allocation_tail = bool(
        raw_origins
        and raw_origins[-1] == function_ea
        and raw_origins.count(function_ea) > 1
        and observed.transfer_ea is None
    )
    normalized_rows = []
    normalized_synthetic_tail = False
    last_ordinal = len(observed.instruction_observations) - 1
    for ordinal, (live_row, projected_row_instruction) in enumerate(zip(
        observed.instruction_observations,
        projected.instruction_observations,
        strict=True,
    )):
        exact_collapsed_tail = bool(
            ordinal == last_ordinal
            and live_row.instruction_ea is None
            and collapsed_allocation_tail
            and live_row.control_transfer_kind is not None
            and projected_row_instruction.control_transfer_kind
            is live_row.control_transfer_kind
        )
        if (
            live_row.instruction_ea
            not in {projected_row_instruction.instruction_ea, function_ea}
            and not exact_collapsed_tail
        ):
            raise ValueError(
                "observed helper instruction origin is neither projected nor "
                "allocation EA: "
                f"helper={owner_ref.local_block_id} serial={observed.serial} "
                f"ordinal={ordinal} live={live_row.instruction_ea!r} "
                f"projected={projected_row_instruction.instruction_ea!r} "
                f"allocation=0x{function_ea:X}"
            )
        normalized_row = replace(
            live_row,
            instruction_ea=projected_row_instruction.instruction_ea,
        )
        if normalized_row != projected_row_instruction:
            raw_tail = (
                block.insn_snapshots[-1]
                if ordinal == last_ordinal and block.insn_snapshots
                else None
            )
            exact_backend_goto_encoding = bool(
                ordinal == last_ordinal
                and projected_row_instruction.opcode == -1
                and projected_row_instruction.raw_opcode is None
                and projected_row_instruction.instruction_kind is InsnKind.GOTO
                and projected_row_instruction.control_transfer_kind
                is ControlTransferKind.GOTO
                and live_row.opcode >= 0
                and live_row.raw_opcode == live_row.opcode
                and live_row.instruction_kind is InsnKind.GOTO
                and live_row.control_transfer_kind is ControlTransferKind.GOTO
                and observed.block_kind is BlockKind.ONE_WAY
                and len(observed.successor_serials) == 1
                and type(raw_tail) is InsnSnapshot
                and raw_tail.opcode == live_row.opcode
                and raw_tail.raw_opcode == live_row.raw_opcode
                and raw_tail.kind is InsnKind.GOTO
                and raw_tail.control_transfer_kind is ControlTransferKind.GOTO
                and raw_tail.is_unconditional_jump
                and not raw_tail.is_conditional_jump
                and not raw_tail.is_call
                and raw_tail.call_kind is None
                and raw_tail.branch_predicate is None
                and raw_tail.predicate_kind is None
                and type(raw_tail.l) is MopSnapshot
                and raw_tail.l.kind is OperandKind.BLOCK
                and raw_tail.l.block_ref == observed.successor_serials[0]
                and raw_tail.r is None
                and raw_tail.d is None
            )
            if exact_backend_goto_encoding:
                normalized_row = replace(
                    normalized_row,
                    opcode=projected_row_instruction.opcode,
                    raw_opcode=projected_row_instruction.raw_opcode,
                    display_text=projected_row_instruction.display_text,
                )
            if normalized_row != projected_row_instruction:
                differing_fields = tuple(
                    field_name
                    for field_name in (
                        "opcode",
                        "width",
                        "instruction_kind",
                        "control_transfer_kind",
                        "is_call",
                        "call_kind",
                        "display_text",
                        "predicate_observation",
                        "raw_opcode",
                    )
                    if getattr(normalized_row, field_name)
                    != getattr(projected_row_instruction, field_name)
                )
                raise ValueError(
                    "observed helper body differs from projected helper body: "
                    f"helper={owner_ref.local_block_id} serial={observed.serial} "
                    f"ordinal={ordinal} fields={differing_fields!r}"
                )
            normalized_synthetic_tail = True
        normalized_rows.append(normalized_row)
    return replace(
        observed,
        native_instruction_eas=projected.native_instruction_eas,
        instruction_observations=tuple(normalized_rows),
        transfer_ea=projected.transfer_ea,
        tail_opcode=(
            projected.tail_opcode if normalized_synthetic_tail
            else observed.tail_opcode
        ),
        raw_tail_opcode=(
            projected.raw_tail_opcode if normalized_synthetic_tail
            else observed.raw_tail_opcode
        ),
        tail_kind=(
            projected.tail_kind if normalized_synthetic_tail
            else observed.tail_kind
        ),
    )


def _is_bound_originless_structural_stop(
    block: BlockSnapshot,
    *,
    owner_ref: PlanBlockRef,
    owner_anchor_ea: int | None,
    phase: model.UnflattenAuthorityPhase,
    planned_serials: Mapping[PlanBlockRef, int] | None,
    observed_patch_binding: ObservedPatchBinding | None,
) -> bool:
    """Recognize the sole anchorless helper shape admitted after live folding."""
    return (
        phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
        and observed_patch_binding is not None
        and planned_serials is not None
        and owner_anchor_ea is None
        and planned_serials.get(owner_ref) == block.serial
        and (owner_ref, block.serial) in observed_patch_binding.bindings
        and block.kind is BlockKind.STOP
        and not block.insn_snapshots
        and not block.succs
        and block.start_ea == 0xFFFFFFFFFFFFFFFF
        and not (
            type(getattr(block, "native_start_ea", None)) is int
            and 0 <= block.native_start_ea < 0xFFFFFFFFFFFFFFFF
        )
    )


def _bounded_native_origin_text(values: tuple[int, ...], *, limit: int = 8) -> str:
    """Render a bounded native-origin sequence without object reprs."""
    shown = ",".join(f"0x{value:X}" for value in values[:limit])
    suffix = "" if len(values) <= limit else f",...+{len(values) - limit}"
    return f"({shown}{suffix})"


def _bounded_serial_text(values: tuple[int, ...], *, limit: int = 8) -> str:
    """Render bounded predecessor/successor serials for a rejection trace."""
    shown = ",".join(str(value) for value in values[:limit])
    suffix = "" if len(values) <= limit else f",...+{len(values) - limit}"
    return f"({shown}{suffix})"


def _observed_native_origin_mismatch_diagnostics(
    *,
    block_rows: list[model.InventoryBlockObservation],
    blocks_by_serial: Mapping[int, BlockSnapshot],
    proposal: model.ProposedUnflattenContract,
    plan: PatchPlan,
    function_ea: int,
) -> None:
    """Log native-origin deltas with the exact binder's classification.

    This is deliberately diagnostic-only.  ``bind_inventory_subjects`` remains
    the sole acceptance authority and still performs the exact comparison.
    Admitted anchor-preserving subsets are low-noise debug evidence; only
    deltas that binding will reject are warning-level mismatches.
    """
    catalog_witnesses = {
        witness.block_ref: witness
        for witness in proposal.source_identity_catalog.blocks
    }
    descriptors = canonical_patch_step_descriptors(plan)
    for row in block_rows:
        ref = row.block_ref
        if type(ref) is not NativeBlockRef:
            continue
        witness = catalog_witnesses.get(ref)
        if witness is None or row.native_instruction_eas == witness.native_instruction_eas:
            continue
        expected = tuple(witness.native_instruction_eas)
        if model._phase_native_origin_subset_preserves_anchor(
            ref,
            witness.anchor_ea,
            row.native_instruction_eas,
            expected,
        ):
            if logger.debug_on:
                logger.debug(
                    "observed unflatten native-origin subset accepted "
                    "blk%d@0x%X supplied=%s expected=%s",
                    row.serial,
                    row.anchor_ea if row.anchor_ea is not None else witness.anchor_ea,
                    _bounded_native_origin_text(row.native_instruction_eas),
                    _bounded_native_origin_text(expected),
                )
            continue
        identity_origins = tuple(sorted(ref.identity.exact_instruction_eas))
        block = blocks_by_serial.get(row.serial)
        if block is None:
            continue
        anchor = row.anchor_ea
        if anchor is None:
            anchor = expected[0] if expected else identity_origins[0]
        raw_origins = producer_api.native_instruction_origins(block)
        instruction_rows = []
        for ordinal, instruction in enumerate(block.insn_snapshots[:8]):
            targets = tuple(
                operand.block_ref
                for operand in (instruction.l, instruction.r, instruction.d)
                if operand is not None
                and operand.kind is OperandKind.BLOCK
                and type(operand.block_ref) is int
            )
            target = "none" if not targets else "/".join(str(item) for item in targets[:4])
            if len(targets) > 4:
                target = f"{target}/...+{len(targets) - 4}"
            instruction_rows.append(
                "ord=%d ea=0x%X native_ea=%s opcode=%d raw_opcode=%s "
                "control=%s target=%s" % (
                    ordinal,
                    instruction.ea,
                    (
                        f"0x{instruction.native_ea:X}"
                        if type(instruction.native_ea) is int
                        else "none"
                    ),
                    instruction.opcode,
                    (
                        str(instruction.raw_opcode)
                        if instruction.raw_opcode is not None else "none"
                    ),
                    (
                        instruction.control_transfer_kind.value
                        if instruction.control_transfer_kind is not None else "none"
                    ),
                    target,
                )
            )
        if len(block.insn_snapshots) > 8:
            instruction_rows.append(f"...+{len(block.insn_snapshots) - 8}")
        matching_descriptors = tuple(
            descriptor
            for descriptor in descriptors
            if ref in descriptor.owner_refs or ref in descriptor.route_refs
        )
        descriptor_rows = tuple(
            f"#{descriptor.step_index}:{descriptor.step_type}:{descriptor.step_digest[:16]}"
            for descriptor in matching_descriptors[:8]
        )
        if len(matching_descriptors) > 8:
            descriptor_rows += (f"...+{len(matching_descriptors) - 8}",)
        raw_instruction_eas = tuple(
            instruction.ea for instruction in block.insn_snapshots
        )
        raw_native_eas = tuple(
            instruction.native_ea
            for instruction in block.insn_snapshots
            if type(instruction.native_ea) is int
        )
        logger.warning(
            "observed unflatten native-origin mismatch "
            "blk%d@0x%X supplied=%s expected=%s identity_expected=%s "
            "block_kind=%s preds=%s succs=%s raw_origins=%s "
            "function_entry=0x%X "
            "raw_origins_contain_function_entry=%s "
            "raw_instruction_eas_contain_function_entry=%s "
            "raw_native_eas_contain_function_entry=%s "
            "instructions=[%s] step_descriptors=[%s]",
            row.serial,
            anchor,
            _bounded_native_origin_text(row.native_instruction_eas),
            _bounded_native_origin_text(expected),
            _bounded_native_origin_text(identity_origins),
            row.block_kind.value,
            _bounded_serial_text(row.predecessor_serials),
            _bounded_serial_text(row.successor_serials),
            _bounded_native_origin_text(raw_origins),
            function_ea,
            function_ea in raw_origins,
            function_ea in raw_instruction_eas,
            function_ea in raw_native_eas,
            "; ".join(instruction_rows),
            "; ".join(descriptor_rows),
        )


def _build_semantic_graph_inventory(
    graph: FlowGraph,
    proposal: model.ProposedUnflattenContract,
    plan: PatchPlan,
    *,
    source: bool,
    phase: model.UnflattenAuthorityPhase,
    source_subjects: tuple[model.SemanticSubjectRef, ...] = (),
    source_inventory: model.SemanticGraphInventory | None = None,
    materialization: CanonicalRouteMaterialization | None = None,
    planned_serials: Mapping[PlanBlockRef, int] | None = None,
    observed_patch_binding: ObservedPatchBinding | None = None,
    prepared_authority: model.PreparedUnflattenAuthority | None = None,
) -> model.SemanticGraphInventory:
    """Build one complete source or candidate inventory.

    This is the sole owner of serial projection, reachability, effect/terminal
    discovery, subject construction, and topology materialization.
    """

    if source:
        if source_inventory is not None:
            raise ValueError("source inventory builder must not receive a source inventory")
    elif source_inventory is not None:
        if type(source_inventory) is not model.SemanticGraphInventory:
            raise TypeError("source_inventory must be SemanticGraphInventory or None")
        model.validate_semantic_graph_inventory(source_inventory)
        if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("candidate source inventory must be producer forecast")
        if source_inventory.generation != proposal.source_identity_catalog.generation:
            raise ValueError("candidate source inventory generation differs from proposal")

    if observed_patch_binding is not None:
        if type(observed_patch_binding) is not ObservedPatchBinding:
            raise TypeError(
                "observed_patch_binding must be ObservedPatchBinding or None"
            )
        validate_observed_patch_binding(observed_patch_binding)
        if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
            raise ValueError("observed patch binding only authorizes observed inventory")
        if observed_patch_binding.bound_plan.plan is not plan:
            raise ValueError("observed patch binding is foreign to inventory plan")
        bound_helper_rows = tuple(
            (ref, serial)
            for ref, serial in observed_patch_binding.bindings
            if type(ref) is PlanBlockRef
        )
        if planned_serials is None or bound_helper_rows != tuple(planned_serials.items()):
            raise ValueError("observed helper bindings differ from observed patch binding")
    projected_reference_inventory = None
    if prepared_authority is not None:
        if type(prepared_authority) is not model.PreparedUnflattenAuthority:
            raise TypeError(
                "prepared_authority must be PreparedUnflattenAuthority or None"
            )
        prepared_authority.__post_init__()
        if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
            raise ValueError(
                "prepared authority only authorizes observed inventory"
            )
        if observed_patch_binding is None:
            raise ValueError(
                "prepared observed inventory requires exact observed patch binding"
            )
        if (
            prepared_authority.owning_plan is not plan
            or prepared_authority.proposal is not proposal
            or prepared_authority.source_inputs is None
        ):
            raise ValueError("prepared authority differs from inventory occurrence")
        projected_reference_inventory = (
            prepared_authority.source_inputs.candidate_inventory
        )
        if (
            projected_reference_inventory.phase
            is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
        ):
            raise ValueError("observed helper reference must be projected preflight")
        if (
            projected_reference_inventory.generation
            != proposal.source_identity_catalog.generation
            or projected_reference_inventory.function_ea != graph.func_ea
        ):
            raise ValueError("projected helper reference graph coordinates differ")
    if materialization is None:
        capture = (
            capture_source_route_materialization
            if source else capture_projected_route_materialization
        )
        materialization = capture(
            graph, generation=proposal.source_identity_catalog.generation,
        )
    if materialization.blocks and materialization.entry_serial != graph.entry_serial:
        raise ValueError("route materialization entry differs from graph")
    if materialization.generation != proposal.source_identity_catalog.generation:
        raise ValueError("route materialization generation differs from inventory")
    blocks_by_serial = materialization.blocks
    candidate_identity_resolution = None
    if source:
        serial_by_ref = _catalog_serials(
            graph, proposal, plan, blocks=blocks_by_serial,
        )
    else:
        candidate_identity_resolution = _resolve_candidate_identities(
            graph, proposal, blocks=blocks_by_serial, plan=plan,
            planned_serials=planned_serials, phase=phase,
            projected_reference_inventory=projected_reference_inventory,
            source_inventory=source_inventory,
            observed_patch_binding=observed_patch_binding,
        )
        serial_by_ref = dict(candidate_identity_resolution.serial_bindings)
    reachable = _semantic_reachable_serials(
        blocks_by_serial,
        entry_serial=graph.entry_serial,
        serial_by_ref=serial_by_ref,
        proposal=proposal,
        require_all_semantic_roots=source,
    )
    fingerprint = materialization.graph_fingerprint
    block_rows = []
    effects = []
    terminals = []
    # Inventory every cached block once.  Reachability remains an explicit
    # closure field used by gates/evidence; it is not the row set itself.
    for serial in sorted(blocks_by_serial):
        block = blocks_by_serial[serial]
        owner_ref = next((ref for ref, value in serial_by_ref.items() if value == serial), None)
        if (
            phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
            and owner_ref is None
            and block.kind is BlockKind.ONE_WAY
            and len(block.succs) == 1
            and block.insn_snapshots
            and block.insn_snapshots[-1].kind is InsnKind.GOTO
            and not _is_exact_unconditional_goto_to(block, block.succs[0])
        ):
            raise ValueError(
                "unowned observed GOTO helper disagrees with its CFG edge"
            )
        owner_anchor = None
        observation_owner_ref = owner_ref
        if owner_ref is not None:
            owner_anchor = next(
                (
                    item.anchor_ea
                    for item in proposal.source_identity_catalog.blocks
                    if item.block_ref == owner_ref
                ),
                None,
            )
            if owner_anchor is None:
                owner_anchor = getattr(block, "native_start_ea", None)
            if owner_anchor is None:
                owner_anchor = getattr(block, "start_ea", None)
            if (
                type(owner_ref) is PlanBlockRef
                and (
                    type(owner_anchor) is not int
                    or not 0 <= owner_anchor < 0xFFFFFFFFFFFFFFFF
                )
            ):
                owner_anchor = _bound_plan_helper_anchor_from_exact_origins(
                    block,
                )
            if (
                type(owner_ref) is PlanBlockRef
                and block.kind is BlockKind.STOP
                and block.start_ea == 0xFFFFFFFFFFFFFFFF
                and (owner_anchor is not None or block.insn_snapshots or block.succs)
            ):
                raise ValueError(
                    "originless planned helper must be an exact structural STOP",
                )
            if (
                type(owner_ref) is PlanBlockRef
                and owner_anchor is None
            ):
                if observed_patch_binding is None:
                    raise ValueError(
                        "originless planned helper requires exact observed binding",
                    )
                if not _is_bound_originless_structural_stop(
                    block,
                    owner_ref=owner_ref,
                    owner_anchor_ea=owner_anchor,
                    phase=phase,
                    planned_serials=planned_serials,
                    observed_patch_binding=observed_patch_binding,
                ):
                    raise ValueError(
                        "originless planned helper must be an exact structural STOP",
                    )
                observation_owner_ref = None
            if (
                type(owner_ref) is LogicalBlockRef
                and type(owner_anchor) is int
                and owner_anchor == 0xFFFFFFFFFFFFFFFF
            ):
                owner_anchor = None
            if (
                owner_anchor is None
                and type(owner_ref) not in (LogicalBlockRef, PlanBlockRef)
            ):
                raise ValueError("planned block has no exact native anchor")
        observed = producer_api.observe_inventory_block(
            block, owner_ref=observation_owner_ref, owner_anchor_ea=owner_anchor,
        )
        recorded_tail = (
            None
            if candidate_identity_resolution is None
            else dict(candidate_identity_resolution.synthetic_tail_origins).get(serial)
        )
        relocated_stop_tail_receipt = next(
            (
                receipt
                for receipt in (() if candidate_identity_resolution is None else candidate_identity_resolution.relocated_stop_tail_receipts)
                if receipt.observed_owner_serial == serial
            ),
            None,
        )
        if relocated_stop_tail_receipt is not None:
            if recorded_tail is not None:
                raise ValueError("relocated STOP receipt overlaps another synthetic tail")
            recorded_tail = _consume_observed_relocated_stop_tail_receipt(
                relocated_stop_tail_receipt,
                observed_patch_binding=observed_patch_binding,
                owner_ref=owner_ref,
                observed_owner_serial=serial,
            )
        synthetic_tail_origin = recorded_tail
        if synthetic_tail_origin is not None:
            if relocated_stop_tail_receipt is not None:
                observed = _normalize_observed_relocated_stop_tail_origin(
                    observed,
                    receipt=relocated_stop_tail_receipt,
                    observed_patch_binding=observed_patch_binding,
                )
            else:
                normalized_tail = replace(
                    observed.instruction_observations[-1], instruction_ea=None,
                )
                observed = replace(
                    observed,
                    native_instruction_eas=tuple(
                        ea for ea in observed.native_instruction_eas
                        if ea != synthetic_tail_origin
                    ),
                    instruction_observations=(
                        *observed.instruction_observations[:-1], normalized_tail,
                    ),
                    transfer_ea=None,
                )
        if (
            type(owner_ref) is PlanBlockRef
            and observed.anchor_ea is not None
            and observed.anchor_ea not in observed.native_instruction_eas
        ):
            if projected_reference_inventory is None:
                raise ValueError(
                    "observed helper allocation EAs require the exact projected inventory"
                )
            projected_rows = tuple(
                row for row in projected_reference_inventory.blocks
                if row.block_ref == owner_ref
            )
            if len(projected_rows) != 1:
                raise ValueError(
                    "observed helper has no unique projected helper occurrence"
                )
            observed = _normalize_observed_plan_helper_allocation_origins(
                block=block,
                observed=observed,
                projected=projected_rows[0],
                owner_ref=owner_ref,
                observed_patch_binding=observed_patch_binding,
                function_ea=graph.func_ea,
            )
        block_rows.append(observed)
        block_effects, block_terminals = model.resolve_inventory_block_sites(
            serial=observed.serial, owner_ref=observed.block_ref,
            owner_anchor_ea=observed.anchor_ea if observed.anchor_ea is not None else 0,
            block_kind=observed.block_kind,
            successor_serials=observed.successor_serials,
            instruction_observations=observed.instruction_observations,
        )
        if (
            type(owner_ref) is PlanBlockRef
            and observed.anchor_ea is None
            and (block_effects or block_terminals)
        ):
            raise ValueError("originless planned helper cannot carry semantic sites")
        effects.extend(block_effects)
        terminals.extend(block_terminals)
    effects = tuple(sorted(effects, key=lambda item: (
        item.owner_serial, item.instruction_ordinal, item.instruction_ea,
        item.effect_kind.value,
    )))
    terminals = tuple(sorted(terminals, key=lambda item: (
        item.owner_serial, item.instruction_ordinal is None,
        item.instruction_ordinal if item.instruction_ordinal is not None else -1,
        item.instruction_ea, item.terminal_kind.value,
    )))
    planned_helpers = {
        ref: next(
            block.anchor_ea if block.anchor_ea is not None
            else min(block.native_instruction_eas)
            for block in block_rows
            if block.serial == serial
        )
        for ref, serial in serial_by_ref.items()
        if not source and type(ref) is PlanBlockRef
        and next(
            block.anchor_ea is not None
            for block in block_rows
            if block.serial == serial
        )
    }
    discovered_subjects = _inventory_subjects(
        proposal,
        serial_by_ref,
        tuple(item for item in effects if item.owner_serial in reachable),
        tuple(item for item in terminals if item.owner_serial in reachable),
        plan,
        planned_helpers=planned_helpers,
    )
    if source:
        subjects = discovered_subjects
        source_subject_ids = tuple(item.subject_id for item in subjects)
    else:
        if type(source_subjects) is not tuple or any(type(item) is not model.SemanticSubjectRef for item in source_subjects):
            raise TypeError("source_subjects must be exact semantic subjects")
        subjects = tuple(sorted({item.subject_id: item for item in (*source_subjects, *discovered_subjects)}.values(), key=lambda item: item.subject_id))
        source_subject_ids = tuple(sorted(item.subject_id for item in source_subjects))
    binding_serial_by_ref = {
        ref: serial
        for ref, serial in serial_by_ref.items()
        if not (
            type(ref) is PlanBlockRef
            and next(
                block.anchor_ea is None
                for block in block_rows
                if block.serial == serial
            )
        )
    }
    if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        _observed_native_origin_mismatch_diagnostics(
            block_rows=block_rows,
            blocks_by_serial=blocks_by_serial,
            proposal=proposal,
            plan=plan,
            function_ea=graph.func_ea,
        )
    bindings = (
        authority_bind.bind_subjects(
            subjects, catalog=proposal.source_identity_catalog,
            phase=phase, graph_fingerprint=fingerprint,
            generation=proposal.source_identity_catalog.generation,
            # Anchorless logical function-exit route subjects bind their exact
            # LogicalBlockRef and source serial; native subjects remain bound
            # through the source identity catalog.
            serial_by_ref=binding_serial_by_ref,
        ) if source else authority_bind.bind_inventory_subjects(
            subjects, catalog=proposal.source_identity_catalog,
            phase=phase, graph_fingerprint=fingerprint,
            generation=proposal.source_identity_catalog.generation,
            serial_by_ref=binding_serial_by_ref,
            effects=tuple(item for item in effects if item.owner_serial in reachable),
            terminals=tuple(item for item in terminals if item.owner_serial in reachable),
            reachable_serials=tuple(sorted(reachable)),
            native_instruction_eas_by_ref=(
                {
                    ref: next(
                        (
                            row.native_instruction_eas
                            for row in block_rows
                            if row.block_ref == ref
                        ),
                        (),
                    )
                    for ref in binding_serial_by_ref
                }
                if any(
                    isinstance(
                        step,
                        (
                            PatchRedirectGoto,
                            PatchRedirectBranch,
                            PatchConvertToGoto,
                            PatchLowerConditionalStateTransition,
                            PatchConditionalRedirect,
                            PatchEdgeSplitTrampoline,
                            PatchEdgeSplitCorridor,
                        ),
                    )
                    for step in plan.steps
                ) else None
            ),
            source_inventory=source_inventory,
            observed_logical_endpoint_occurrences=(
                ()
                if candidate_identity_resolution is None
                else candidate_identity_resolution.logical_endpoint_occurrences
            ),
        )
    )
    topology = []
    for row in block_rows:
        for peer in row.successor_serials:
            topology.append(model.InventoryTopologyIncidence(
                model.TopologyIncidenceKind.SUCCESSOR, row.serial, peer,
                row.transfer_ea,
            ))
        for peer in row.predecessor_serials:
            peer_row = next((item for item in block_rows if item.serial == peer), None)
            topology.append(model.InventoryTopologyIncidence(
                model.TopologyIncidenceKind.PREDECESSOR, row.serial, peer,
                None if peer_row is None else peer_row.transfer_ea,
            ))
    topology = tuple(sorted(topology, key=lambda item: (
        item.kind.value, item.owner_serial, item.peer_serial,
        item.source_transfer_ea if item.source_transfer_ea is not None else -1,
    )))
    observed_route_topology_occurrences = _mint_observed_route_topology_occurrences(
        blocks=blocks_by_serial,
        serial_by_ref=serial_by_ref,
        projected_inventory=projected_reference_inventory,
        realization=(
            None if prepared_authority is None
            else prepared_authority.projected_route_realization
        ),
        patch_facts=(
            () if prepared_authority is None
            else prepared_authority.source_inputs.patch_step_facts
        ),
    )
    observed_lowered_conditional_topology_occurrences = (
        _mint_observed_lowered_conditional_topology_occurrences(
            blocks=blocks_by_serial,
            serial_by_ref=serial_by_ref,
            projected_inventory=projected_reference_inventory,
            realization=(
                None if prepared_authority is None
                else prepared_authority.projected_route_realization
            ),
            patch_facts=(
                () if prepared_authority is None
                else prepared_authority.source_inputs.patch_step_facts
            ),
            plan=plan,
        )
    )
    route_domains = {
        frozenset((pair.source_subject_id, pair.target_subject_id))
        for occurrence in observed_route_topology_occurrences
        for pair in occurrence.normalized_pairs
    }
    conditional_domains = {
        frozenset((pair.source_subject_id, pair.target_subject_id))
        for occurrence in observed_lowered_conditional_topology_occurrences
        for pair in occurrence.normalized_pairs
    }
    if route_domains & conditional_domains:
        raise ValueError(
            "observed route and lowered conditional topology authority overlap",
        )
    reachable_tuple = tuple(sorted(reachable))
    digest = semantic_graph_inventory_digest(
        phase, fingerprint, proposal.source_identity_catalog.generation,
        tuple(block_rows), subjects, bindings, effects, terminals, topology,
        reachable_tuple, graph.entry_serial, source_subject_ids, graph.func_ea,
        observed_route_topology_occurrences,
        observed_lowered_conditional_topology_occurrences,
    )
    return model.SemanticGraphInventory(
        phase, fingerprint, proposal.source_identity_catalog.generation,
        tuple(block_rows), subjects, bindings, effects, terminals, topology, digest,
        reachable_tuple,
        materialization.entry_serial,
        source_subject_ids,
        function_ea=graph.func_ea,
        observed_route_topology_occurrences=observed_route_topology_occurrences,
        observed_lowered_conditional_topology_occurrences=(
            observed_lowered_conditional_topology_occurrences
        ),
    )


def _receipt(
    proposal, metrics, *, source_inventory, candidate_inventory,
    generic_gate_facts=None, source_route_authority=None,
    projected_route_realization=None, conditional_relations=(),
    patch_step_facts=(), _preparation_inputs=None,
):
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("source_inventory must be SemanticGraphInventory")
    if type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("candidate_inventory must be SemanticGraphInventory")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
    _validate_observed_logical_occurrence_provenance(candidate_inventory)
    if _preparation_inputs is None:
        projected_topology_reference = candidate_inventory
    else:
        if type(_preparation_inputs) is not model.DerivedUnflattenPreparationInputs:
            raise TypeError("sealed preparation inputs must be transaction-owned")
        projected_topology_reference = _preparation_inputs.projected_topology_reference
        if type(projected_topology_reference) is not model.SemanticGraphInventory:
            raise TypeError("sealed topology reference must be SemanticGraphInventory")
        model.validate_semantic_graph_inventory(projected_topology_reference)
    model.validate_preparation_build_metrics(metrics)
    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("proposal must be ProposedUnflattenContract")
    if generic_gate_facts is not None and type(generic_gate_facts) is not gates.GenericCfgGateFacts:
        raise TypeError("generic_gate_facts must be GenericCfgGateFacts or None")
    synthetic_route_pair = (
        source_route_authority is None
        and projected_route_realization is None
    )
    if not synthetic_route_pair:
        if type(source_route_authority) is not model.SourceBoundRouteAuthority:
            raise TypeError("source_route_authority must be SourceBoundRouteAuthority")
        if type(projected_route_realization) is not model.ProjectedRouteRealization:
            raise TypeError("projected_route_realization must be ProjectedRouteRealization")
        if projected_route_realization.source_authority is not source_route_authority:
            raise ValueError("projected realization must use exact source authority")
    ordered_source_subjects = tuple(sorted(
        source_inventory.subjects, key=lambda item: item.subject_id,
    ))
    ordered_candidate_subjects = tuple(sorted(
        candidate_inventory.subjects, key=lambda item: item.subject_id,
    ))
    ordered_source_bindings = tuple(sorted(
        source_inventory.bindings, key=lambda item: item.subject.subject_id,
    ))
    ordered_candidate_bindings = tuple(sorted(
        candidate_inventory.bindings, key=lambda item: item.subject.subject_id,
    ))
    values = {
        "proposal_id": authority_id(proposal), "plan_id": proposal.plan_id,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "candidate_fingerprint": candidate_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "candidate_generation": candidate_inventory.generation,
        "source_inventory_digest": source_inventory.inventory_digest,
        "candidate_inventory_digest": candidate_inventory.inventory_digest,
        "source_binding_digest": authority_id(ordered_source_bindings),
        "candidate_binding_digest": authority_id(ordered_candidate_bindings),
        "route_expansion_digest": authority_id(tuple(
            item for item in ordered_source_subjects
            if item.kind is model.SemanticSubjectKind.ROUTE
        )),
        "effect_catalog_digest": authority_id(tuple(
            item.subject_id for item in ordered_source_subjects
            if item.role is model.SemanticSubjectRole.EFFECT_SITE
        )),
        "terminal_catalog_digest": authority_id(tuple(
            item.subject_id for item in ordered_source_subjects
            if item.role is model.SemanticSubjectRole.TERMINAL_SITE
        )),
        "plan_input_digest": authority_id(tuple(
            item.subject_id for item in ordered_source_subjects
            if item.role in {
                model.SemanticSubjectRole.SOURCE_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
            }
        )),
        "dispatcher_member_digest": authority_id(tuple(
            item.subject_id for item in ordered_source_subjects
            if item.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        )),
        "planned_helper_digest": authority_id(tuple(
            item.subject_id for item in ordered_candidate_subjects
            if item.role is model.SemanticSubjectRole.PLANNED_HELPER
        )),
        # Receipts normalize patch facts by plan occurrence, matching the
        # evaluator's closed receipt check.  Fact-ID ordering is unrelated to
        # execution order and diverges once an otherwise valid extra step is
        # present (for example, an anchored self redirect).
        "patch_step_digest": authority_id(tuple(sorted(
            patch_step_facts,
            key=lambda item: (item.plan_id, item.step_index),
        ))),
        "conditional_relation_digest": authority_id(tuple(conditional_relations)),
        "metrics": metrics,
        "generic_gate_facts_digest": authority_id(generic_gate_facts) if generic_gate_facts is not None else None,
        "source_route_authority_id": (
            None if synthetic_route_pair else source_route_authority.source_authority_id
        ),
        "projected_route_realization_id": (
            None if synthetic_route_pair else projected_route_realization.realization_id
        ),
        "retirement_candidate_catalog": proposal.retirement_candidate_catalog,
        "corridor_coverage_forecast": proposal.corridor_coverage_forecast,
        "projected_topology_reference_digest": projected_topology_reference.inventory_digest,
    }
    return model.PreparationAuthorityReceipt.mint(**values)


def _derive_local_alias_transaction_facts(
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
) -> tuple[
    tuple[authority_bind._LocalAliasClaimFactOccurrence, ...],
    tuple[model.PatchStepEvidencePayload, ...],
    tuple[model.ConditionalSubjectRelation, ...],
]:
    """Derive exact alias patch facts and STORE-loss authority.

    Both LOAD and STORE alias accesses are mechanical scalarization steps and
    therefore enter the closed patch receipt.  Only STORE -> MOV changes the
    effect catalogue, so only STORE steps mint semantic-loss claims.
    """

    if plan.source_generation is not None and plan.source_generation != source_inventory.generation:
        raise ValueError("local-alias plan generation differs from source inventory")

    claims: list[model.LocalAliasEffectScalarizationClaim] = []
    patch_facts: list[model.PatchStepEvidencePayload] = []
    occurrences: list[authority_bind._LocalAliasClaimFactOccurrence] = []
    relations: list[model.ConditionalSubjectRelation] = []
    source_coordinates = dict(plan.source_coordinates)
    blocks_by_serial = {block.serial: block for block in source_inventory.blocks}
    source_catalog_bindings_by_ref = {
        binding.block_ref: binding
        for binding in source_inventory.bindings
        if binding.block_ref is not None
        and binding.status is model.SubjectBindingStatus.UNIQUE
        and binding.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
    }
    owner_subjects = {
        subject.block_ref: subject
        for subject in source_inventory.subjects
        if subject.kind is model.SemanticSubjectKind.BLOCK
        and subject.role is model.SemanticSubjectRole.EFFECT_SITE
    }
    seen_hosts: set[tuple[object, int, int]] = set()
    for step_index, step in enumerate(plan.steps):
        if type(step) is not PatchScalarizeLocalAliasAccess:
            continue
        _validate_local_alias_step(step)
        serial = source_coordinates.get(step.block_serial)
        if type(serial) is not int:
            raise ValueError("local-alias step owner lacks an exact source coordinate")
        binding = source_catalog_bindings_by_ref.get(step.block_serial)
        owner_subject = owner_subjects.get(step.block_serial)
        block = blocks_by_serial.get(serial)
        if binding is None or owner_subject is None or block is None:
            raise ValueError("local-alias step owner is not uniquely bound")
        if serial not in source_inventory.reachable_serials:
            raise ValueError("local-alias step owner is unreachable")
        host_key = (step.block_serial, step.host_ea, step.host_opcode)
        if host_key in seen_hosts:
            raise ValueError("local-alias step owner is ambiguous")
        seen_hosts.add(host_key)
        if (
            binding.serial != serial
            or step.host_ea not in binding.native_instruction_eas
            or owner_subject.anchor_ea != binding.anchor_ea
        ):
            raise ValueError("local-alias step owner binding is stale")
        observations = tuple(
            item for item in block.instruction_observations
            if item.instruction_ea == step.host_ea
            and item.opcode == step.host_opcode
        )
        if len(observations) != 1:
            raise ValueError(
                "local-alias step must identify one exact LOAD or STORE observation"
            )
        observation = observations[0]
        if (
            observation.instruction_kind not in {model.InsnKind.LOAD, model.InsnKind.STORE}
            or observation.raw_opcode is None
            or observation.is_call
            or observation.call_kind is not None
            or observation.control_transfer_kind is not None
        ):
            raise ValueError("local-alias step host is not an exact LOAD or STORE")
        display_text = observation.display_text
        if display_text is None:
            raise ValueError("local-alias step host lacks exact text provenance")
        if re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(step.alias_token)}(?![A-Za-z0-9_])",
            display_text,
        ) is None:
            raise ValueError("local-alias tokens do not match exact host text")
        if step.host_text_sha1 is not None and hashlib.sha1(
            display_text.encode("utf-8", errors="replace")
        ).hexdigest()[:16] != step.host_text_sha1:
            raise ValueError("local-alias host text digest is stale")
        if step.value_size is not None and step.value_size != observation.width:
            raise ValueError("local-alias step value size disagrees with its host")
        step_digest = authority_id(_local_alias_step_preimage(step_index, step))
        patch_fact = model.PatchStepEvidencePayload(
            plan.plan_id, step_index, "PatchScalarizeLocalAliasAccess",
            step.block_serial, step_digest, step.host_ea, step.host_opcode,
            step.value_size,
        )
        patch_facts.append(patch_fact)
        if observation.instruction_kind is model.InsnKind.LOAD:
            continue
        effects = tuple(
            item for item in source_inventory.effects
            if item.owner_serial == serial
            and item.instruction_ea == step.host_ea
            and item.opcode == step.host_opcode
            and item.effect_kind is model.EffectSiteKind.STORE
        )
        if len(effects) != 1:
            raise ValueError("local-alias STORE must identify one exact effect site")
        source_site = effects[0]
        if (
            observation.ordinal != source_site.instruction_ordinal
            or observation.width != source_site.width
            or block.block_ref != source_site.owner_ref
            or block.anchor_ea != source_site.owner_anchor_ea
        ):
            raise ValueError("local-alias STORE observation differs from its effect site")
        claim = _claim_factory(
            model.LocalAliasEffectScalarizationClaim,
            kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
            owner_subject=owner_subject,
            step_index=step_index,
            host_ea=step.host_ea,
            host_opcode=step.host_opcode,
            alias_token=step.alias_token,
            base_token=step.base_token,
            host_text_sha1=step.host_text_sha1,
            value_size=step.value_size,
            step_digest=step_digest,
            source_generation=source_inventory.generation,
        )
        effect_subject = next(
            subject for subject in source_inventory.subjects
            if subject.kind is model.SemanticSubjectKind.EFFECT
            and subject.role is model.SemanticSubjectRole.EFFECT_SITE
            and subject.block_ref == step.block_serial
            and subject.anchor_ea == owner_subject.anchor_ea
            and getattr(subject.locator, "instruction_ea", None) == step.host_ea
            and getattr(subject.locator, "effect_kind", None) is model.EffectSiteKind.STORE
        )
        relations.append(model.ConditionalSubjectRelation(
            owner_subject.subject_id,
            effect_subject.subject_id,
            model.SafetyDimension.EFFECT_PRESERVATION,
            authority_id(("local-alias-effect", step_digest, effect_subject.subject_id)),
        ))
        claims.append(claim)
        occurrences.append(authority_bind._LocalAliasClaimFactOccurrence(
            claim=claim,
            patch_step_fact=patch_fact,
            source_site=source_site,
            source_observation=observation,
        ))
    ordered_occurrences = tuple(sorted(
        occurrences, key=lambda item: item.claim.claim_id,
    ))
    return (
        ordered_occurrences,
        tuple(sorted(patch_facts, key=authority_bind.patch_step_fact_id)),
        tuple(sorted(relations, key=lambda item: (
            item.source_subject_id, item.target_subject_id,
            item.dimension.value, item.provenance_id,
        ))),
    )


@dataclass(frozen=True, slots=True)
class _StructuralStopPatchPreimage:
    """One exact ownerless STOP used only as a redirect's old edge."""

    block_ref: LogicalBlockRef
    serial: int


@dataclass(frozen=True, slots=True)
class _NativeSourceEdgePatchPreimage:
    """One exact native old edge consumed only as redirect provenance.

    The old target is not a semantic route subject.  It is retained here only
    so transaction binding can verify the plan replaces a source edge that
    actually existed in the immutable source inventory.
    """

    source_ref: NativeBlockRef
    target_ref: NativeBlockRef
    source_serial: int
    target_serial: int


@dataclass(frozen=True, slots=True)
class _NativeConditionalSuffixPatchPreimage:
    """One exact non-route GOTO owner in a paired conditional triangle."""

    branch_owner_ref: NativeBlockRef
    suffix_owner_ref: NativeBlockRef
    old_target_ref: NativeBlockRef
    branch_owner_serial: int
    suffix_owner_serial: int
    old_target_serial: int


def _native_source_edge_patch_preimage(
    *,
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
    step: object,
    ref_position: int,
    ref: object,
) -> _NativeSourceEdgePatchPreimage | None:
    """Classify an exact native old edge without granting semantic authority.

    A redirect may replace a physical branch arm whose old target is outside
    the selected semantic route closure.  That target remains non-semantic:
    admission requires its immutable coordinate and reciprocal source edge,
    while later realization and loss gates still decide whether the redirect
    has a supported semantic meaning.
    """

    if (
        type(step) not in {PatchRedirectGoto, PatchRedirectBranch}
        or ref_position != 1
        or type(ref) is not NativeBlockRef
        or ref != step.old_target
        or type(step.from_serial) is not NativeBlockRef
    ):
        return None
    expected_kind = (
        BlockKind.ONE_WAY
        if type(step) is PatchRedirectGoto
        else BlockKind.TWO_WAY
    )
    source_coordinates = tuple(
        int(serial)
        for coordinate_ref, serial in plan.source_coordinates
        if coordinate_ref == step.from_serial
    )
    target_coordinates = tuple(
        int(serial)
        for coordinate_ref, serial in plan.source_coordinates
        if coordinate_ref == ref
    )
    if len(source_coordinates) != 1 or len(target_coordinates) != 1:
        return None
    source_serial, target_serial = source_coordinates[0], target_coordinates[0]
    if (
        source_inventory.serial_by_ref.get(step.from_serial) != source_serial
        or source_inventory.serial_by_ref.get(ref) != target_serial
    ):
        return None
    source_rows = tuple(
        row for row in source_inventory.blocks if row.serial == source_serial
    )
    target_rows = tuple(
        row for row in source_inventory.blocks if row.serial == target_serial
    )
    if (
        len(source_rows) != 1
        or len(target_rows) != 1
        or source_rows[0].block_ref != step.from_serial
        or target_rows[0].block_ref != ref
        or source_rows[0].block_kind is not expected_kind
        or target_serial not in source_rows[0].successor_serials
        or source_serial not in target_rows[0].predecessor_serials
    ):
        return None
    return _NativeSourceEdgePatchPreimage(
        step.from_serial, ref, source_serial, target_serial,
    )


def _native_conditional_suffix_patch_preimage(
    *,
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
    step_index: int,
    step: object,
    ref_position: int,
    ref: object,
    route_refs: set[object],
) -> _NativeConditionalSuffixPatchPreimage | None:
    """Bind the physical suffix owner of one adjacent branch/GOTO pair.

    The producer may lower a selected conditional triangle by redirecting the
    selected branch arm and its one-way fallthrough suffix to the same route
    target.  The suffix is physical patch provenance, not a semantic subject.
    Require the exact adjacent plan pair and reciprocal source triangle before
    allowing its owner reference to cross patch-lineage validation.
    """

    if (
        type(step) is not PatchRedirectGoto
        or type(step) is PatchRedirectBranch
        or type(step_index) is not int
        or step_index <= 0
        or ref_position != 0
        or type(ref) is not NativeBlockRef
        or ref != step.from_serial
        or step.new_target not in route_refs
    ):
        return None
    branch = plan.steps[step_index - 1]
    if (
        type(branch) is not PatchRedirectBranch
        or type(branch.from_serial) is not NativeBlockRef
        or branch.from_serial != step.new_target
        or branch.old_target != step.old_target
        or branch.new_target != step.new_target
        or branch.new_target != branch.from_serial
    ):
        return None
    branch_edge = _native_source_edge_patch_preimage(
        source_inventory=source_inventory,
        plan=plan,
        step=branch,
        ref_position=1,
        ref=branch.old_target,
    )
    suffix_edge = _native_source_edge_patch_preimage(
        source_inventory=source_inventory,
        plan=plan,
        step=step,
        ref_position=1,
        ref=step.old_target,
    )
    if branch_edge is None or suffix_edge is None:
        return None
    blocks = {row.serial: row for row in source_inventory.blocks}
    branch_row = blocks.get(branch_edge.source_serial)
    suffix_row = blocks.get(suffix_edge.source_serial)
    old_target_row = blocks.get(branch_edge.target_serial)
    if (
        branch_row is None
        or suffix_row is None
        or old_target_row is None
        or suffix_edge.target_serial != branch_edge.target_serial
        or len(branch_row.successor_serials) != 2
        or set(branch_row.successor_serials)
        != {suffix_edge.source_serial, branch_edge.target_serial}
        or suffix_row.predecessor_serials != (branch_edge.source_serial,)
        or suffix_row.successor_serials != (branch_edge.target_serial,)
        or not {
            branch_edge.source_serial, suffix_edge.source_serial,
        } <= set(old_target_row.predecessor_serials)
    ):
        return None
    return _NativeConditionalSuffixPatchPreimage(
        branch.from_serial,
        step.from_serial,
        step.old_target,
        branch_edge.source_serial,
        suffix_edge.source_serial,
        branch_edge.target_serial,
    )


def _structural_stop_patch_preimage(
    *,
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
    step: object,
    ref_position: int,
    ref: object,
) -> _StructuralStopPatchPreimage | None:
    """Classify the sole non-semantic reference admitted in a patch preimage.

    An instructionless structural STOP is deliberately absent from the source
    identity catalog and semantic subjects.  A native route may nevertheless
    replace the exact old edge to that STOP.  Bind that physical preimage
    through the immutable plan coordinate and the already-validated inventory
    shape; never promote it into route authority.
    """

    if (
        type(step) is not PatchRedirectGoto
        or ref_position != 1
        or type(ref) is not LogicalBlockRef
        or step.old_target != ref
    ):
        return None
    coordinates = tuple(
        int(serial)
        for coordinate_ref, serial in plan.source_coordinates
        if coordinate_ref == ref
    )
    if len(coordinates) != 1:
        return None
    serial = coordinates[0]
    rows = tuple(row for row in source_inventory.blocks if row.serial == serial)
    if len(rows) != 1 or not model._is_unowned_structural_stop_row(rows[0]):
        return None
    return _StructuralStopPatchPreimage(ref, serial)


def _derive_patch_lineage_facts(
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
    *,
    semantic_admission: bool = False,
) -> tuple[model.PatchStepEvidencePayload, ...]:
    """Derive helper/resegmentation step evidence once at the transaction edge."""

    source_refs = set(source_inventory.serial_by_ref)
    source_logical_exit_refs = {
        block.block_ref
        for block in source_inventory.blocks
        if (
            type(block.block_ref) is LogicalBlockRef
            and block.predecessor_serials
            and model.is_exact_logical_function_exit_inventory_row(block)
        )
    }
    route_refs = (
        _selected_route_subject_refs(plan.unflatten_proposal)
        if plan.unflatten_proposal is not None
        else set()
    )
    entry_frontier_refs = (
        _source_entry_dispatcher_frontier_refs(
            source_inventory, plan.unflatten_proposal,
        )
        if plan.unflatten_proposal is not None
        else set()
    )
    rows: list[model.PatchStepEvidencePayload] = []
    helper_specs = {
        spec.block_id: (spec_index, spec)
        for spec_index, spec in enumerate(plan.new_blocks)
    }
    if len(helper_specs) != len(plan.new_blocks):
        raise ValueError("plan helper specifications must have unique block IDs")
    for step_index, step in enumerate(plan.steps):
        try:
            descriptor = canonical_patch_step_descriptor(plan, step_index)
        except (TypeError, ValueError):
            # A nominal planner step is authority-owned even when its
            # canonical preimage is malformed.  Do not silently drop such a
            # step and later report an unrelated helper-ownership failure.
            # Structural derivation deliberately does not consume proposed
            # entry-liveness allowances.  Their receipt is minted only after
            # this neutral fact set exists; any later semantic admission must
            # consume that receipt, never planner assertion.
            if semantic_admission and type(step) in {
                PatchConditionalRedirect, PatchConvertToGoto,
                PatchLowerConditionalStateTransition,
                PatchRedirectGoto, PatchRedirectBranch,
                PatchEdgeSplitTrampoline, PatchEdgeSplitCorridor,
            }:
                raise
            continue
        step_type = type(step).__name__
        owners = descriptor.owner_refs
        refs = descriptor.route_refs
        host_ea = descriptor.host_ea
        host_opcode = descriptor.host_opcode
        structural_preimages = tuple(
            preimage
            for ref_position, ref in enumerate(refs)
            if (
                preimage := _structural_stop_patch_preimage(
                    source_inventory=source_inventory,
                    plan=plan,
                    step=step,
                    ref_position=ref_position,
                    ref=ref,
                )
            ) is not None
        )
        structural_preimage_refs = {
            preimage.block_ref for preimage in structural_preimages
        }
        native_source_edge_preimages = tuple(
            preimage
            for ref_position, ref in enumerate(refs)
            if (
                preimage := _native_source_edge_patch_preimage(
                    source_inventory=source_inventory,
                    plan=plan,
                    step=step,
                    ref_position=ref_position,
                    ref=ref,
                )
            ) is not None
        )
        structural_preimage_refs.update(
            preimage.target_ref for preimage in native_source_edge_preimages
        )
        conditional_suffix_preimages = tuple(
            preimage
            for ref_position, ref in enumerate(refs)
            if (
                preimage := _native_conditional_suffix_patch_preimage(
                    source_inventory=source_inventory,
                    plan=plan,
                    step_index=step_index,
                    step=step,
                    ref_position=ref_position,
                    ref=ref,
                    route_refs=route_refs,
                )
            ) is not None
        )
        structural_preimage_refs.update(
            preimage.suffix_owner_ref
            for preimage in conditional_suffix_preimages
        )

        def foreign_reference_error(
            ref_position: int,
            ref: object,
        ) -> ValueError:
            serial = source_inventory.serial_by_ref.get(ref)
            anchor = next(
                (
                    block.anchor_ea
                    for block in source_inventory.blocks
                    if block.serial == serial
                ),
                None,
            )
            serial_anchor = (
                f"{serial}@{anchor:#x}"
                if type(anchor) is int else f"{serial}@None"
            )
            logical_coordinates = (
                repr(ref) if type(ref) is LogicalBlockRef else None
            )
            source_coordinate_candidates = tuple(
                serial
                for coordinate_ref, serial in plan.source_coordinates
                if coordinate_ref == ref
            )
            return ValueError(
                "patch-step reference is foreign to the source plan: "
                f"step={step_index} kind={step_type} "
                f"ref_position={ref_position} ref_type={type(ref).__name__} "
                f"source_member={ref in source_refs} "
                f"route_member={ref in route_refs} "
                f"structural_preimage={ref in structural_preimage_refs} "
                f"serial_anchor={serial_anchor} "
                f"logical_ref={logical_coordinates} "
                f"source_coordinate_candidates={source_coordinate_candidates}"
            )

        for owner in owners:
            if type(owner) is PlanBlockRef:
                if owner.plan_id != plan.plan_id:
                    raise ValueError("patch-step owner belongs to a foreign plan")
            elif type(owner) is LogicalBlockRef:
                if owner not in route_refs:
                    raise ValueError("patch-step owner is foreign to the source or plan")
            elif type(owner) is NativeBlockRef:
                if owner not in source_refs and owner not in route_refs:
                    raise ValueError("patch-step owner is foreign to the source or plan")
            else:
                raise ValueError("patch-step owner is foreign to the source or plan")
            helper_spec = helper_specs.get(owner) if type(owner) is PlanBlockRef else None
            if type(owner) is PlanBlockRef and helper_spec is None:
                raise ValueError("patch-step helper owner lacks exactly one creation spec")
            owner_preimage = ("owner", owner)
            for ref_position, ref in enumerate(refs):
                if ref is None:
                    continue
                if type(ref) is PlanBlockRef:
                    if ref.plan_id != plan.plan_id:
                        raise ValueError("patch-step reference belongs to a foreign plan")
                    continue
                if type(ref) is LogicalBlockRef:
                    if (
                        ref in source_logical_exit_refs
                        or ref in route_refs
                        or ref in structural_preimage_refs
                    ):
                        continue
                    raise foreign_reference_error(ref_position, ref)
                if type(ref) is NativeBlockRef and (
                    ref in source_refs or ref in route_refs
                ):
                    continue
                if ref in structural_preimage_refs:
                    continue
                else:
                    raise foreign_reference_error(ref_position, ref)
            allowed_corridor_refs = {
                proposal_ref
                for proposal_ref in (
                    plan.unflatten_proposal.plan_inputs.source_entry_ref,
                    plan.unflatten_proposal.plan_inputs.dispatcher_entry_ref,
                    *plan.unflatten_proposal.plan_inputs.dispatcher_member_refs,
                )
                if proposal_ref is not None
            } if plan.unflatten_proposal is not None else set()
            if plan.unflatten_proposal is not None:
                forecast = plan.unflatten_proposal.corridor_coverage_forecast
                if forecast is not None:
                    forecast = model.corridor_base_forecast(forecast)
                    allowed_corridor_refs.update(
                        node.block_ref
                        for path in forecast.paths
                        for node in path.nodes
                    )
                    dispatcher_serial = source_inventory.serial_by_ref.get(
                        forecast.dispatcher_ref
                    )
                    if dispatcher_serial is not None:
                        successor_serials = {
                            successor
                            for block in source_inventory.blocks
                            if block.serial == dispatcher_serial
                            for successor in block.successor_serials
                        }
                        allowed_corridor_refs.update(
                            block.block_ref
                            for block in source_inventory.blocks
                            if block.serial in successor_serials
                            and block.block_ref is not None
                        )
            if type(step) in {
                PatchConvertToGoto, PatchLowerConditionalStateTransition,
                PatchRedirectGoto, PatchRedirectBranch,
            } and route_refs:
                entry_bridge_refs = set()
                if type(step) in {PatchRedirectGoto, PatchRedirectBranch}:
                    source_ref, old_target_ref, new_target_ref = refs
                    if (
                        source_ref in entry_frontier_refs
                        and old_target_ref
                        == plan.unflatten_proposal.plan_inputs.dispatcher_entry_ref
                        and new_target_ref in route_refs
                    ):
                        entry_bridge_refs.add(source_ref)
                missing_route_refs = {
                    ref for ref in refs if ref is not None
                } - route_refs - allowed_corridor_refs - entry_bridge_refs \
                    - structural_preimage_refs - source_logical_exit_refs
                if missing_route_refs:
                    selected_proof_ids = {
                        proof_id
                        for claim in plan.unflatten_proposal.claims
                        if type(claim) is model.EquivalentSemanticRouteClaim
                        for proof_id in claim.route_proof_ids
                    }
                    selected_proof_rows = tuple(
                        (
                            proof.proof_kind.value,
                            source_inventory.serial_by_ref.get(next((
                                row.block_ref
                                for row in plan.unflatten_proposal.source_identity_catalog.blocks
                                if type(row.block_ref) is NativeBlockRef
                                and row.block_ref.identity == proof.source_identity
                            ), None)),
                            source_inventory.serial_by_ref.get(next((
                                row.block_ref
                                for row in plan.unflatten_proposal.source_identity_catalog.blocks
                                if type(row.block_ref) is NativeBlockRef
                                and row.block_ref.identity == proof.source_owner_identity
                            ), None)),
                            tuple(
                                (
                                    destination.state_constant,
                                    source_inventory.serial_by_ref.get(next((
                                        row.block_ref
                                        for row in plan.unflatten_proposal.source_identity_catalog.blocks
                                        if type(row.block_ref) is NativeBlockRef
                                        and row.block_ref.identity == destination.target_identity
                                    ), None)),
                                )
                                for destination in proof.destinations
                            ),
                            None if proof.bootstrap is None else tuple(
                                source_inventory.serial_by_ref.get(next((
                                    row.block_ref
                                    for row in plan.unflatten_proposal.source_identity_catalog.blocks
                                    if type(row.block_ref) is NativeBlockRef
                                    and row.block_ref.identity == point.identity
                                ), None))
                                for point in proof.bootstrap.corridor
                            ),
                        )
                        for proof in plan.unflatten_proposal.route_evidence.route_proofs
                        if proof.proof_id in selected_proof_ids
                    )
                    raise ValueError(
                        "patch-step source and destination refs are outside proposal "
                        f"route subjects: step={step_index} kind={type(step).__name__} "
                        "refs="
                        f"{tuple((index, source_inventory.serial_by_ref.get(ref)) for index, ref in enumerate(refs))!r} "
                        "missing="
                        f"{tuple(sorted([(source_inventory.serial_by_ref.get(ref), ref) for ref in missing_route_refs], key=lambda item: (item[0] is None, item[0], repr(item[1]))))!r} "
                        f"route_closure={tuple(sorted(source_inventory.serial_by_ref.get(ref) for ref in route_refs if source_inventory.serial_by_ref.get(ref) is not None))!r} "
                        f"entry_frontier={tuple(sorted(source_inventory.serial_by_ref.get(ref) for ref in entry_frontier_refs if source_inventory.serial_by_ref.get(ref) is not None))!r} "
                        f"entry={source_inventory.entry_serial!r} "
                        f"dispatcher={source_inventory.serial_by_ref.get(plan.unflatten_proposal.plan_inputs.dispatcher_entry_ref)!r} "
                        f"terminals={tuple((terminal.owner_serial, terminal.owner_anchor_ea, terminal.instruction_ea, terminal.terminal_kind.value) for terminal in source_inventory.terminals)!r} "
                        f"entry_neighborhood={tuple((block.serial, block.predecessor_serials, block.successor_serials) for block in source_inventory.blocks if block.serial <= 6)!r} "
                        f"selected_proofs={selected_proof_rows!r}"
                    )
            if fact_descriptor := descriptor:
                step_digest = fact_descriptor.step_digest
            rows.append(model.PatchStepEvidencePayload(
                plan.plan_id, step_index, step_type, owner, step_digest,
                host_ea, host_opcode, None,
                dict(fact_descriptor.new_block_spec_digests).get(owner),
            ))
    owned_helpers = {
        fact.owner_ref for fact in rows if type(fact.owner_ref) is PlanBlockRef
    }
    helper_owner_counts = {
        helper_ref: sum(1 for fact in rows if fact.owner_ref == helper_ref)
        for helper_ref in helper_specs
    }
    if owned_helpers != set(helper_specs) or any(
        count != 1 for count in helper_owner_counts.values()
    ):
        raise ValueError("every plan helper specification must have one exact patch-step owner")
    return tuple(rows)


def _derive_transaction_facts(
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
) -> authority_bind._DerivedTransactionClaimInventory:
    """Derive the complete transaction fact set at one authority boundary.

    Revalidation must replay this exact function.  Keeping alias and
    patch-lineage derivation behind one entry point prevents a later caller
    from silently comparing a Task 12 plan against the Task 11-only replay.
    """

    alias_occurrences, alias_patch_facts, alias_relations = (
        _derive_local_alias_transaction_facts(source_inventory, plan)
    )
    alias_claims = tuple(item.claim for item in alias_occurrences)
    route_patch_step_facts = _derive_patch_lineage_facts(source_inventory, plan)
    patch_step_facts = tuple(sorted(
        (*alias_patch_facts, *route_patch_step_facts),
        key=authority_bind.patch_step_fact_id,
    ))
    claims = tuple(sorted(
        (*plan.unflatten_proposal.claims, *alias_claims),
        key=lambda item: item.claim_id,
    ))
    return authority_bind._mint_derived_transaction_claim_inventory(
        proposal=plan.unflatten_proposal,
        plan=plan,
        source_inventory=source_inventory,
        proposal_claims=plan.unflatten_proposal.claims,
        local_alias_occurrences=alias_occurrences,
        claims=claims,
        route_patch_step_facts=route_patch_step_facts,
        local_patch_step_facts=alias_patch_facts,
        patch_step_facts=patch_step_facts,
        legacy_conditional_relations=alias_relations,
    )


def _derive_patch_lineage_relations(
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
    patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
) -> tuple[model.ConditionalSubjectRelation, ...]:
    """Bind each patch step to exact source/candidate block witnesses."""

    source_subjects = tuple(
        subject for subject in source_inventory.subjects
        if subject.role is model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK
    )
    candidate_subjects = tuple(
        subject for subject in candidate_inventory.subjects
        if subject.role in {
            model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK,
            model.SemanticSubjectRole.PLANNED_HELPER,
        }
    )
    candidate_bindings = {
        item.subject.subject_id: item for item in candidate_inventory.bindings
    }
    relations: list[model.ConditionalSubjectRelation] = []
    for fact in patch_step_facts:
        step = plan.steps[fact.step_index]
        if (
            type(step) is PatchRedirectBranch
            and step.fallthrough_helper_block_id is not None
            and type(fact.owner_ref) is not PlanBlockRef
        ):
            # The native source owner is carried as exact patch evidence for
            # evaluator use-def projection, but helper lineage relations are
            # established only by the helper-owned fact.
            continue
        try:
            descriptor = canonical_patch_step_descriptor(plan, fact.step_index)
        except (TypeError, ValueError):
            continue
        refs = descriptor.route_refs
        source_ref = next((ref for ref in refs if type(ref) is not PlanBlockRef), None)
        owner = fact.owner_ref
        helper_spec = next(
            (spec for spec in plan.new_blocks if spec.block_id == owner), None
        ) if type(owner) is PlanBlockRef else None
        if helper_spec is not None and helper_spec.template_block is not None:
            source_ref = helper_spec.template_block
        if source_ref is None:
            raise ValueError("patch-step lineage lacks an exact source reference")
        sources = tuple(item for item in source_subjects if item.block_ref == source_ref)
        candidates = tuple(item for item in candidate_subjects if item.block_ref == owner)
        if not sources:
            # Not every mechanical patch fact materializes a source block
            # relation (for example a pure terminal-cycle operation).  Only
            # facts with a source catalog identity participate in the
            # canonical physical-loss relation.
            continue
        # A removed source owner intentionally has no candidate physical
        # witness.  Its canonical loss cell is classified by the bound claim,
        # not repaired by inventing a role-matched target.
        if not candidates:
            continue
        if len(sources) != 1 or len(candidates) != 1:
            raise ValueError("patch-step lineage requires one canonical physical witness")
        paired = ((sources[0], candidates[0]),)
        for source, candidate in paired:
            binding = candidate_bindings.get(candidate.subject_id)
            if binding is None or binding.status is not model.SubjectBindingStatus.UNIQUE:
                raise ValueError("patch-step lineage candidate witness is not unique")
            relations.append(model.ConditionalSubjectRelation(
                source.subject_id,
                candidate.subject_id,
                model.SafetyDimension.STRUCTURAL_ACCOUNTING,
                authority_id(("patch-lineage", fact.step_digest,
                              source.subject_id, candidate.subject_id,
                              binding.native_instruction_eas)),
            ))
    return tuple(sorted(relations, key=lambda item: (
        item.source_subject_id, item.target_subject_id,
        item.dimension.value, item.provenance_id,
    )))


def _local_alias_step_preimage(
    step_index: int, step: PatchScalarizeLocalAliasAccess,
) -> tuple[object, ...]:
    """Return the canonical, closed representation of an alias step.

    ``PatchScalarizeLocalAliasAccess`` is a planner record and deliberately is
    not part of the semantic-authority codec.  The transaction boundary still
    needs a stable digest of every field that becomes semantic authority, so
    digest the exact typed fields rather than passing the planner object to the
    canonical encoder.
    """

    return (
        "PatchScalarizeLocalAliasAccess",
        step_index,
        step.block_serial,
        step.host_ea,
        step.host_opcode,
        step.alias_token,
        step.base_token,
        step.host_text_sha1,
        step.value_size,
    )


def _validate_local_alias_step(step: PatchScalarizeLocalAliasAccess) -> None:
    """Revalidate the planner record at the semantic authority boundary."""

    if type(step) is not PatchScalarizeLocalAliasAccess:
        raise TypeError("local-alias step must be nominal")
    owner = step.block_serial
    if type(owner) not in (NativeBlockRef, LogicalBlockRef):
        raise TypeError("local-alias owner must be NativeBlockRef or LogicalBlockRef")
    try:
        owner.__post_init__()
    except (TypeError, ValueError) as error:
        raise ValueError("local-alias owner reference is malformed") from error
    if (
        type(step.host_ea) is not int
        or not 0 <= step.host_ea < 0xFFFFFFFFFFFFFFFF
    ):
        raise TypeError("local-alias host_ea must be an exact native EA")
    if type(step.host_opcode) is not int or step.host_opcode < 0:
        raise TypeError("local-alias host_opcode must be an exact nonnegative int")
    for value, label in (
        (step.alias_token, "alias_token"),
        (step.base_token, "base_token"),
    ):
        if type(value) is not str or not value.strip():
            raise TypeError(f"local-alias {label} must be a nonblank exact string")
    if step.host_text_sha1 is not None and (
        type(step.host_text_sha1) is not str
        or re.fullmatch(r"[0-9a-f]{16}", step.host_text_sha1) is None
    ):
        raise ValueError("local-alias host_text_sha1 must be lowercase 16-hex")
    if step.value_size is not None and (
        type(step.value_size) is not int or step.value_size <= 0
    ):
        raise TypeError("local-alias value_size must be an exact positive int")


def _bind_detached_authority_results(
    *,
    claims,
    source_inventory,
    candidate_inventory,
    corridor_result,
    phase,
    prior_source_results=(),
):
    """Carry one sealed detached source authority through transaction phases."""

    if type(claims) is not tuple:
        raise TypeError("claims must be an exact tuple")
    detached_claims = tuple(
        claim for claim in claims
        if type(claim) is model.DetachedDeadHandlerComponentClaim
    )
    if len({claim.claim_id for claim in detached_claims}) != len(detached_claims):
        raise ValueError("detached claims must not contain duplicate claim IDs")
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("source_inventory must be SemanticGraphInventory")
    if type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("candidate_inventory must be SemanticGraphInventory")
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be UnflattenAuthorityPhase")
    if type(prior_source_results) is not tuple:
        raise TypeError("prior_source_results must be an exact tuple")
    if any(
        type(item) is not model.DetachedDeadHandlerComponentSourceResult
        for item in prior_source_results
    ):
        raise TypeError("prior_source_results must contain sealed detached source results")
    if corridor_result is not None:
        # Detached-component compatibility is deliberately expressed against
        # the legacy corridor partition, but the transaction retains the one
        # enclosing authority union in its preparation inputs.
        corridor_result = model.corridor_base_phase_result(corridor_result)

    expected_claim_ids = {claim.claim_id for claim in detached_claims}
    prior_claim_ids = tuple(item.claim_id for item in prior_source_results)
    foreign_claim_ids = set(prior_claim_ids) - expected_claim_ids
    if foreign_claim_ids:
        raise ValueError("foreign projected source result")
    if len(set(prior_claim_ids)) != len(prior_claim_ids):
        raise ValueError("duplicate projected source result")
    if not detached_claims:
        return (), ()
    if corridor_result is None:
        raise ValueError("detached claim requires sealed corridor coverage")

    if phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        if prior_source_results:
            raise ValueError("projected detached claim must mint source authority exactly once")
        sources = []
        phase_results = []
        for claim in detached_claims:
            binding_result = authority_bind.bind_detached_dead_handler_component_claim(
                claim=claim,
                source_inventory=source_inventory,
                candidate_inventory=candidate_inventory,
                corridor_result=corridor_result,
                phase=phase,
            )
            sources.append(binding_result.source_result)
            phase_results.append(binding_result.phase_result)
        return (
            tuple(sorted(sources, key=lambda item: item.result_id)),
            tuple(sorted(phase_results, key=lambda item: item.result_id)),
        )

    if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        raise ValueError("detached authority only binds projected or observed phases")
    prior_by_claim = {item.claim_id: item for item in prior_source_results}
    if set(prior_by_claim) != expected_claim_ids:
        raise ValueError("observed detached claim requires exactly one projected source result")
    sources = []
    phase_results = []
    for claim in detached_claims:
        sealed_source = prior_by_claim[claim.claim_id]
        binding_result = authority_bind.bind_detached_dead_handler_component_claim(
            claim=claim,
            source_inventory=source_inventory,
            candidate_inventory=candidate_inventory,
            corridor_result=corridor_result,
            phase=phase,
            source_result=sealed_source,
        )
        if binding_result.source_result is not sealed_source:
            raise AssertionError(
                "observed detached validation did not reuse sealed source authority"
            )
        sources.append(sealed_source)
        phase_results.append(binding_result.phase_result)
    return (
        tuple(sorted(sources, key=lambda item: item.result_id)),
        tuple(sorted(phase_results, key=lambda item: item.result_id)),
    )


def _bind_projected_corridor_authority(
    *,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
    source_route_authority: model.SourceBoundRouteAuthority | None,
) -> model.CorridorCoveragePhaseResultAuthority | None:
    """Mint exactly one projected corridor authority at the transaction edge."""

    forecast = proposal.corridor_coverage_forecast
    if forecast is None:
        return None
    if type(forecast) is model.CorridorCoverageForecast:
        return authority_bind.bind_corridor_coverage_forecast(
            proposal=proposal,
            source_inventory=source_inventory,
            candidate_inventory=candidate_inventory,
            phase=phase,
        )
    if type(forecast) is model.DefaultGapInfeasibilityForecast:
        if type(source_route_authority) is not model.SourceBoundRouteAuthority:
            raise TypeError("default-gap projected binding requires source route authority")
        return authority_bind.bind_default_gap_infeasibility_forecast(
            proposal=proposal,
            source_inventory=source_inventory,
            candidate_inventory=candidate_inventory,
            phase=phase,
            source_authority=source_route_authority,
        )
    raise TypeError("corridor forecast must be a closed authority record")


def _revalidate_observed_corridor_authority(
    *,
    projected_result: model.CorridorCoveragePhaseResultAuthority | None,
    proposal: model.ProposedUnflattenContract,
    claims: tuple[model.UnflattenClaim, ...],
    source_inventory: model.SemanticGraphInventory,
    observed_inventory: model.SemanticGraphInventory,
    source_route_authority: model.SourceBoundRouteAuthority | None,
) -> model.CorridorCoveragePhaseResultAuthority | None:
    """Revalidate the exact projected union without re-planning route authority."""

    forecast = proposal.corridor_coverage_forecast
    if forecast is None:
        if projected_result is not None:
            raise ValueError("observed corridor result lacks its forecast")
        return None
    if type(forecast) is model.CorridorCoverageForecast:
        if projected_result is not None and type(projected_result) is not model.CorridorCoveragePhaseResult:
            raise TypeError("legacy corridor forecast requires legacy prepared result")
        return authority_bind.revalidate_observed_corridor_coverage(
            projected_result=projected_result,
            proposal=proposal,
            claims=claims,
            source_inventory=source_inventory,
            observed_inventory=observed_inventory,
        )
    if type(forecast) is model.DefaultGapInfeasibilityForecast:
        if type(projected_result) is not model.DefaultGapInfeasibilityPhaseResult:
            raise TypeError("default-gap forecast requires exact prepared phase result")
        if type(source_route_authority) is not model.SourceBoundRouteAuthority:
            raise TypeError("default-gap observed validation requires source route authority")
        return authority_bind.revalidate_observed_default_gap_infeasibility(
            projected_result=projected_result,
            proposal=proposal,
            source_inventory=source_inventory,
            observed_inventory=observed_inventory,
            source_authority=source_route_authority,
        )
    raise TypeError("corridor forecast must be a closed authority record")


def _derive_inputs(
    source_inventory, candidate_inventory, plan, proposal, generic_gates, *,
    phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    candidate_generation=None,
    phase_build_metrics,
    preparation_metrics,
    source_route_authority=None,
    projected_route_realization=None,
    derived_claim_inventory=None,
    generic_gate_facts=None,
    preparation_inputs=None,
):
    """Assemble immutable facts; semantic evidence belongs to the evaluator."""

    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("source_inventory must be SemanticGraphInventory")
    if type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("candidate_inventory must be SemanticGraphInventory")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
    _validate_observed_logical_occurrence_provenance(candidate_inventory)
    if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        if type(preparation_inputs) is not model.DerivedUnflattenPreparationInputs:
            raise TypeError(
                "observed derivation requires transaction-owned preparation inputs"
            )
        # Persistence validates equal inventories by content, but the live
        # transaction must carry the exact projected occurrence it prepared.
        if (
            preparation_inputs.projected_topology_reference
            is not preparation_inputs.candidate_inventory
        ):
            raise ValueError(
                "observed derivation requires the exact prepared projected topology occurrence"
            )
        projected_topology_reference = preparation_inputs.projected_topology_reference
    else:
        if preparation_inputs is not None:
            raise TypeError("preparation inputs are only valid for observed derivation")
        projected_topology_reference = candidate_inventory
    if type(projected_topology_reference) is not model.SemanticGraphInventory:
        raise TypeError("projected topology reference must be SemanticGraphInventory")
    model.validate_semantic_graph_inventory(projected_topology_reference)
    terminal_cycle_phase_results = []
    detached_phase_results = []
    detached_source_results = []
    retirement_phase_results = []
    if phase is model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        for claim in proposal.claims:
            if type(claim) is model.DetachedDeadHandlerComponentClaim:
                # Coverage is bound once below; defer until that sealed result exists.
                continue
            if type(claim) is model.RetiredDispatcherInfrastructureClaim:
                binding_result = authority_bind.bind_retired_dispatcher_infrastructure_claim(
                    claim=claim, proposal=proposal,
                    source_inventory=source_inventory,
                    projected_inventory=candidate_inventory,
                    phase=phase,
                )
                expected_source = {
                    item.subject.subject_id: item
                    for item in binding_result.source_bindings
                }
                actual_source = {
                    item.subject.subject_id: item
                    for item in source_inventory.bindings
                    if item.subject.subject_id in expected_source
                }
                expected_projected = {
                    item.subject.subject_id: item
                    for item in binding_result.projected_bindings
                }
                actual_projected = {
                    item.subject.subject_id: item
                    for item in candidate_inventory.bindings
                    if item.subject.subject_id in expected_projected
                }
                if actual_source != expected_source:
                    raise ValueError("retirement binder result is not carried by source facts")
                if actual_projected != expected_projected:
                    raise ValueError("candidate retirement facts drifted from binder result")
                if binding_result.phase_result is None:
                    raise ValueError("retirement binder did not produce a phase result")
                retirement_phase_results.append(binding_result.phase_result)
            elif type(claim) is model.TerminalCycleBreakClaim:
                terminal_binding = authority_bind.bind_terminal_cycle_break_claim(
                    claim=claim,
                    proposal=proposal,
                    source_inventory=source_inventory,
                    candidate_inventory=candidate_inventory,
                    phase=phase,
                )
                terminal_cycle_phase_results.append(
                    terminal_binding.phase_result,
                )
    if type(phase_build_metrics) is not model.PhaseBuildMetrics:
        raise TypeError("phase_build_metrics must be PhaseBuildMetrics")
    model.validate_phase_build_metrics(phase_build_metrics)
    if type(preparation_metrics) is not model.PreparationBuildMetrics:
        raise TypeError("preparation_metrics must be PreparationBuildMetrics")
    model.validate_preparation_build_metrics(preparation_metrics)
    resolved_generic_gate_facts = generic_gate_facts
    if type(generic_gates) is GenericCfgGateBundle:
        validate_generic_cfg_gate_bundle(generic_gates)
        if resolved_generic_gate_facts is None:
            resolved_generic_gate_facts = generic_gates.facts
    elif generic_gates is not None:
        raise TypeError("generic_gates must be GenericCfgGateBundle or None")
    if (
        resolved_generic_gate_facts is not None
        and type(resolved_generic_gate_facts) is not gates.GenericCfgGateFacts
    ):
        raise TypeError("generic_gate_facts must be GenericCfgGateFacts or None")
    if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        # The observed phase is intentionally not a second planning pass.  Its
        # claim, patch, and conditional authority is the exact sealed
        # preparation occurrence; only the candidate inventory is live.
        claims = preparation_inputs.claims
        patch_step_facts = preparation_inputs.patch_step_facts
        conditional_relations = preparation_inputs.conditional_relations
        corridor_coverage_phase_result = _revalidate_observed_corridor_authority(
            projected_result=preparation_inputs.corridor_coverage_phase_result,
            proposal=proposal,
            claims=claims,
            source_inventory=source_inventory,
            observed_inventory=candidate_inventory,
            source_route_authority=source_route_authority,
        )
        retirement_claims = tuple(
            claim for claim in claims
            if type(claim) is model.RetiredDispatcherInfrastructureClaim
        )
        if len(retirement_claims) > 1:
            raise ValueError("observed retirement authority is ambiguous")
        retirement_phase_results = []
        if retirement_claims:
            if preparation_inputs.retirement_phase_result is None:
                raise ValueError("observed retirement claim lacks prepared result")
            retirement_phase_results.append(
                authority_bind.revalidate_observed_retired_dispatcher_infrastructure(
                    projected_result=preparation_inputs.retirement_phase_result,
                    claim=retirement_claims[0], proposal=proposal,
                    source_inventory=source_inventory,
                    observed_inventory=candidate_inventory,
                )
            )
        terminal_by_claim = {
            result.claim_id: result
            for result in preparation_inputs.terminal_cycle_phase_results
        }
        terminal_cycle_phase_results = []
        for claim in claims:
            if type(claim) is not model.TerminalCycleBreakClaim:
                continue
            projected_result = terminal_by_claim.get(claim.claim_id)
            if projected_result is None:
                raise ValueError("observed terminal claim lacks prepared result")
            terminal_cycle_phase_results.append(
                authority_bind.revalidate_observed_terminal_cycle_break(
                    projected_result=projected_result, claim=claim, proposal=proposal,
                    source_inventory=source_inventory,
                    observed_inventory=candidate_inventory,
                )
            )
    else:
        if derived_claim_inventory is None:
            derived_claim_inventory = _derive_transaction_facts(source_inventory, plan)
        patch_step_facts = derived_claim_inventory.patch_step_facts
        conditional_relations = tuple(sorted(
            (*derived_claim_inventory.legacy_conditional_relations, *_derive_patch_lineage_relations(
                source_inventory, candidate_inventory, plan, patch_step_facts,
            )),
            key=lambda item: (item.source_subject_id, item.target_subject_id,
                              item.dimension.value, item.provenance_id),
        ))
        corridor_coverage_phase_result = _bind_projected_corridor_authority(
            proposal=proposal,
            source_inventory=source_inventory,
            candidate_inventory=candidate_inventory,
            phase=phase,
            source_route_authority=source_route_authority,
        )
        claims = derived_claim_inventory.claims
    prior_detached_source_results = ()
    if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        prior_detached_source_results = (
            preparation_inputs.detached_dead_handler_component_source_results
        )
    detached_source_results, detached_phase_results = _bind_detached_authority_results(
        claims=claims,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        corridor_result=corridor_coverage_phase_result,
        phase=phase,
        prior_source_results=prior_detached_source_results,
    )
    if len(retirement_phase_results) > 1:
        raise ValueError("retirement phase must mint exactly one result")
    retirement_phase_result = retirement_phase_results[0] if retirement_phase_results else None
    receipt = _receipt(
        proposal,
        preparation_metrics,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        generic_gate_facts=resolved_generic_gate_facts,
        source_route_authority=source_route_authority,
        projected_route_realization=projected_route_realization,
        conditional_relations=conditional_relations,
        patch_step_facts=patch_step_facts,
        _preparation_inputs=preparation_inputs,
    )
    return model.DerivedUnflattenPreparationInputs(
        proposal=proposal,
        claims=claims,
        preparation_receipt=receipt,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        projected_topology_reference=projected_topology_reference,
        source_route_authority=source_route_authority,
        projected_route_realization=projected_route_realization,
        generic_gate_facts=resolved_generic_gate_facts,
        conditional_relations=conditional_relations,
        patch_step_facts=patch_step_facts,
        preparation_metrics=preparation_metrics,
        phase_build_metrics=phase_build_metrics,
        corridor_coverage_phase_result=corridor_coverage_phase_result,
        detached_dead_handler_component_source_results=tuple(sorted(detached_source_results, key=lambda item: item.result_id)),
        detached_dead_handler_component_phase_results=tuple(sorted(detached_phase_results, key=lambda item: item.result_id)),
        terminal_cycle_phase_results=tuple(sorted(
            terminal_cycle_phase_results, key=lambda item: item.result_id,
        )),
        retirement_phase_result=retirement_phase_result,
    )


def realize_projected_routes(
    *,
    authority_id_value: str,
    derived_claim_inventory: object,
    source_route_authority: model.SourceBoundRouteAuthority,
    attempt_id: TransactionAttemptId,
    projected_inventory: model.SemanticGraphInventory,
    raw_effect_gate_fact: model.RawEffectGatePhaseFact,
    legacy_effective_gate_facts: object,
    entry_liveness_receipts: tuple[model.BoundEntryEndpointLivenessAllowance, ...] = (),
) -> model.ProjectedRouteRealizationResult:
    """Realize the already-derived transaction inventory exactly once.

    This is deliberately the transaction-facing kernel.  Its inputs are the
    exact occurrences built by ``_prepare_unflatten_authority``; it neither
    accepts a caller-created legacy DTO nor rebuilds an equal inventory.
    """
    projected_claim_inventory = authority_bind._bind_transaction_projected_claim_inventory(
        derived=derived_claim_inventory,
        source_authority=source_route_authority,
        attempt_id=attempt_id,
        projected_inventory=projected_inventory,
    )
    return authority_bind._realize_projected_routes_from_claim_inventory(
        authority_id=authority_id_value,
        claim_inventory=projected_claim_inventory,
        raw_effect_gate_fact=raw_effect_gate_fact,
        legacy_effective_gate_facts=legacy_effective_gate_facts,
        entry_liveness_receipts=entry_liveness_receipts,
    )


def _prepare_unflatten_authority_in_session(*, source, projection, plan, attempt_id, generic_gates, _timings=None):
    """Prepare one immutable projected authority case before mutation."""
    from .model import (
        UnflattenAuthorityPreparationAccepted,
        UnflattenAuthorityPreparationRejected,
    )
    if type(source) is not FlowGraph or type(projection) is not CfgProjection:
        raise TypeError("unflatten preparation requires a FlowGraph and CfgProjection")
    if not isinstance(plan, PatchPlan):
        raise TypeError("unflatten preparation requires PatchPlan")
    if projection.plan_id != plan.plan_id or projection.snapshot_id != plan.snapshot_id:
        raise ValueError("projection authority differs from PatchPlan")
    if type(attempt_id) is not TransactionAttemptId:
        raise TypeError("unflatten preparation requires TransactionAttemptId")
    if attempt_id.plan_id != plan.plan_id:
        raise ValueError("preparation attempt belongs to a foreign plan")
    if plan.source_generation is not None and attempt_id.generation != plan.source_generation:
        raise ValueError("preparation attempt generation differs from source plan")
    route = select_plan_route(plan)
    if isinstance(route, UnflattenAuthorityNotApplicable):
        return route
    if not isinstance(route, TypedProposalRoute):
        verdict = model.UnflattenAuthorityVerdict(
            False, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                route.reason, None, None, None,
                _unavailable_candidate_fingerprint(plan.plan_id), None, (),
        )
        proposal_failure = None
        if isinstance(route, RejectedPlanRoute) and route.stage is not None:
            proposal_failure = model.ProposalValidationFailure(
                route.stage, route.detail_code,
            )
        return UnflattenAuthorityPreparationRejected(verdict, proposal_failure)
    proposal = route.proposal
    candidate_fingerprint = None
    source_route_authority = None
    projected_route_realization = None
    try:
        # The producer/transaction seam, in a try of its own.  The references
        # the producer minted are not this scope's to use, so the transaction
        # verifies what the producer binding can still prove and mints its own
        # references in the arena this session owns.  What that check was able
        # to prove depends on the producer path and is recorded, never skipped
        # silently; see ``runtime_authority``.
        #
        # The scope is the point: the preparation body below is several hundred
        # lines under one handler, so a refusal here would otherwise be reported
        # as a generic projected binding failure with the plan's own
        # fingerprint.  A seam refusal is its own stage and says so, exactly as
        # the observed side does.
        route_authority_verification = _record_route_authority_rebind(
            proposal.route_evidence,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )
    except (TypeError, ValueError) as error:
        return _projected_route_authority_rebind_failure(
            "projected_route_authority_rebind", error, proposal=proposal,
        )
    try:
        inventory_started_ns = perf_counter_ns()
        source_materialization = capture_source_route_materialization(
            source, generation=proposal.source_identity_catalog.generation,
        )
        projected_materialization = capture_projected_route_materialization(
            projection.graph, generation=proposal.source_identity_catalog.generation,
        )
        source_inventory = _build_semantic_graph_inventory(
            source, proposal, plan, source=True,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            materialization=source_materialization,
        )
        candidate_inventory = _build_semantic_graph_inventory(
            projection.graph, proposal, plan, source=False,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            source_subjects=source_inventory.subjects,
            source_inventory=source_inventory,
            materialization=projected_materialization,
        )
        inventory_ms = _elapsed_ms(inventory_started_ns, perf_counter_ns())
        if _timings is not None:
            _timings.inventory_ms = inventory_ms
        candidate_fingerprint = candidate_inventory.graph_fingerprint
        phase_build_metrics = model.PhaseBuildMetrics(
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1,
            inventory_ms,
        )
        preparation_metrics = model.PreparationBuildMetrics(
            1, 1, phase_build_metrics.inventory_ms,
        )
        binding_started_ns = perf_counter_ns()
        derived_claim_inventory = _derive_transaction_facts(source_inventory, plan)
        source_binding = authority_bind.bind_source_route_authority(
            proposal=proposal,
            source_inventory=source_inventory,
            source_materialization=source_materialization,
        )
        if type(source_binding) is not model.SourceBoundRouteAuthorityAccepted:
            failures = tuple(
                (
                    failure.stage.value,
                    failure.scope.value,
                    failure.proof_id,
                    tuple(
                        (item.anchor_ea, item.ref)
                        for item in failure.anchored_refs
                    ),
                )
                for failure in source_binding.failures
            )
            raise ValueError(
                f"source route authority binding rejected: {failures!r}"
            )
        source_route_authority = source_binding.authority
        if type(generic_gates) is not GenericCfgGateBundle:
            raise TypeError("applicable unflatten preparation requires generic gates")
        validate_generic_cfg_gate_bundle(generic_gates)
        # ``facts`` is a view property, not a stable occurrence.  Capture it
        # once so raw/effective consumers and the derived transaction case
        # share the same authority object.
        generic_gate_facts = generic_gates.facts
        raw_effect_gate_fact = authority_bind.bind_raw_effect_gate_phase_fact(
            source_inventory=source_inventory,
            projected_inventory=candidate_inventory,
            raw_gate_facts=generic_gate_facts.effectful_raw,
            derived_claim_inventory=derived_claim_inventory,
        )
        legacy_effective_comparison = _legacy_effective_gate_comparison_facts(
            generic_gate_facts.effectful_raw
        )
        entry_liveness_receipts = _admit_bound_entry_endpoint_liveness(
            proposal=proposal,
            receipts=bind_entry_endpoint_liveness_allowances(
                plan=plan,
                allowances=proposal.entry_endpoint_liveness_allowances,
                patch_step_facts=derived_claim_inventory.patch_step_facts,
                source=source,
                projected=projection.graph,
                source_inventory=source_inventory,
                projected_inventory=candidate_inventory,
            ),
            patch_step_facts=derived_claim_inventory.patch_step_facts,
        )
        realization_authority_id = projected_authority_id(
            attempt_id=attempt_id,
            proposal_id=authority_id(proposal),
            source_authority_id=source_route_authority.source_authority_id,
            plan_id=plan.plan_id,
            claims=derived_claim_inventory.claims,
            patch_step_facts=derived_claim_inventory.patch_step_facts,
            source_inventory=source_inventory,
            projected_inventory=candidate_inventory,
            raw_effect_gate_fact=raw_effect_gate_fact,
            entry_liveness_receipts=entry_liveness_receipts,
        )
        realization_result = realize_projected_routes(
            authority_id_value=realization_authority_id,
            derived_claim_inventory=derived_claim_inventory,
            source_route_authority=source_route_authority,
            attempt_id=attempt_id,
            projected_inventory=candidate_inventory,
            raw_effect_gate_fact=raw_effect_gate_fact,
            legacy_effective_gate_facts=legacy_effective_comparison,
            entry_liveness_receipts=entry_liveness_receipts,
        )
        if type(realization_result) is not model.ProjectedRouteRealizationAccepted:
            failure_rows = tuple(
                (
                    failure.stage.value,
                    failure.scope.value,
                    failure.proof_id,
                    failure.step_index,
                    tuple(
                        (source_inventory.serial_by_ref.get(item.ref), item.anchor_ea)
                        for item in failure.anchored_refs
                    ),
                )
                for failure in getattr(realization_result, "failures", ())
            )
            raise ValueError(
                "projected route realization rejected: "
                f"failures={failure_rows!r}"
            )
        projected_route_realization = realization_result.realization
        inputs = _derive_inputs(
            source_inventory, candidate_inventory,
            plan, proposal, generic_gates,
            candidate_generation=attempt_id.generation,
            phase_build_metrics=phase_build_metrics,
            preparation_metrics=preparation_metrics,
            source_route_authority=source_route_authority,
            projected_route_realization=projected_route_realization,
            derived_claim_inventory=derived_claim_inventory,
            generic_gate_facts=generic_gate_facts,
        )
        prepared_authority_id = authority_id((
            proposal,
            inputs.claims,
            inputs.patch_step_facts,
            inputs.conditional_relations,
            inputs.source_inventory.graph_fingerprint,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.source_inventory.generation,
            inputs.candidate_inventory.generation,
            inputs.source_inventory.bindings,
            inputs.candidate_inventory.bindings,
            tuple(receipt.binding_id for receipt in entry_liveness_receipts),
        ))
        if _timings is not None:
            _timings.binding_ms = _elapsed_ms(binding_started_ns, perf_counter_ns())
        evaluation_started_ns = perf_counter_ns()
        case = build_semantic_case(
            authority_id=prepared_authority_id,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )
        verdict = evaluate_case(case)
        if not verdict.accepted:
            physical_entry_reachable = frozenset(
                inputs.candidate_inventory.physical_entry_reachable_serials
            )
            for failed in verdict.failed_obligations:
                if (
                    failed.key.dimension
                    is not model.SafetyDimension.HANDLER_REACHABILITY
                    or failed.key.subject.role
                    is not model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
                    or type(failed.key.subject.locator)
                    is not model.HandlerSubjectLocator
                ):
                    continue
                locator = failed.key.subject.locator
                source_serial = inputs.source_inventory.serial_by_ref.get(
                    locator.block_ref
                )
                candidate_serial = inputs.candidate_inventory.serial_by_ref.get(
                    locator.block_ref
                )
                source_rows = tuple(
                    row
                    for row in inputs.source_inventory.blocks
                    if row.serial == source_serial
                )
                candidate_rows = tuple(
                    row
                    for row in inputs.candidate_inventory.blocks
                    if row.serial == candidate_serial
                )
                matching_claims = tuple(
                    (
                        type(claim).__name__,
                        claim.claim_id,
                        tuple(sorted({
                            subject.role.value
                            for subject in _claim_subjects(claim)
                            if subject.block_ref == locator.block_ref
                        })),
                    )
                    for claim in inputs.claims
                    if any(
                        subject.block_ref == locator.block_ref
                        for subject in _claim_subjects(claim)
                    )
                )
                matching_claim_ids = {
                    claim_id for _kind, claim_id, _roles in matching_claims
                }
                catalog_anchor_by_ref = {
                    row.block_ref: row.anchor_ea
                    for row in proposal.source_identity_catalog.blocks
                }
                realization_rows = tuple(
                    (
                        type(row.relation).__name__,
                        row.claim_id,
                        row.plan_step_index,
                        catalog_anchor_by_ref.get(row.source_ref),
                        catalog_anchor_by_ref.get(row.old_target_ref),
                        (
                            None
                            if row.new_target_ref is None
                            else catalog_anchor_by_ref.get(row.new_target_ref)
                        ),
                        tuple(
                            (role.role.value, role.anchor_ea)
                            for role in row.conditional_roles
                        ),
                    )
                    for row in inputs.projected_route_realization.rows
                    if row.claim_id in matching_claim_ids
                )
                candidate_incoming = tuple(sorted(
                    row.serial
                    for row in inputs.candidate_inventory.blocks
                    if candidate_serial in row.successor_serials
                ))
                logger.warning(
                    "projected handler delivery violation: anchor=0x%x "
                    "source_serial=%r source_pred=%r source_succ=%r "
                    "projected_serial=%r projected_pred=%r projected_incoming=%r "
                    "projected_succ=%r entry_serial=%d physically_reachable=%s "
                    "semantic_reachable=%s normalized_states=%r claims=%r "
                    "route_rows=%r",
                    locator.anchor_ea,
                    source_serial,
                    tuple(
                        row.predecessor_serials for row in source_rows
                    ),
                    tuple(row.successor_serials for row in source_rows),
                    candidate_serial,
                    tuple(
                        row.predecessor_serials for row in candidate_rows
                    ),
                    candidate_incoming,
                    tuple(row.successor_serials for row in candidate_rows),
                    inputs.candidate_inventory.entry_serial,
                    candidate_serial in physical_entry_reachable,
                    candidate_serial
                    in inputs.candidate_inventory.reachable_serials,
                    locator.normalized_states,
                    matching_claims,
                    realization_rows,
                )
            justifications_by_id = {
                item.justification_id: item for item in case.justifications
            }
            for failed in verdict.failed_obligations:
                if failed.state is not model.ObligationState.INCONSISTENT:
                    continue
                cell = next(
                    item for item in case.obligation_index.cells
                    if item.key == failed.key
                )
                sealed_rows = tuple(
                    row
                    for row in inputs.projected_route_realization.site_phase_result.effect_results
                    if row.source_subject_id == failed.key.subject.subject_id
                )
                effect_evidence = tuple(
                    item.payload
                    for item in case.evidence
                    if type(item.payload) is model.EffectSiteEvidencePayload
                    and item.payload.effect_subject_id
                    == failed.key.subject.subject_id
                )
                source_effects = tuple(
                    row for row in inputs.source_inventory.effects
                    if type(failed.key.subject.locator)
                    is model.EffectSubjectLocator
                    and row.owner_ref
                    == failed.key.subject.locator.owner_ref
                    and row.owner_anchor_ea
                    == failed.key.subject.locator.owner_anchor_ea
                    and row.instruction_ea
                    == failed.key.subject.locator.instruction_ea
                    and row.effect_kind
                    is failed.key.subject.locator.effect_kind
                )
                candidate_effects = tuple(
                    row for source_row in source_effects
                    for row in inputs.candidate_inventory.effects
                    if row.instruction_ea == source_row.instruction_ea
                    and row.effect_kind is source_row.effect_kind
                )
                raw_effect = inputs.generic_gate_facts.effectful_raw
                effective_effect = inputs.generic_gate_facts.effectful_effective
                logger.warning(
                    "projected inconsistent obligation: dimension=%s role=%s "
                    "anchor=%r support=%r refute=%r sealed=%r effect=%r "
                    "source_rows=%r candidate_rows=%r raw=%r effective=%r",
                    failed.key.dimension.value,
                    failed.key.subject.role.value,
                    failed.key.subject.anchor_ea,
                    tuple(
                        (
                            justifications_by_id[item].rule.value,
                            justifications_by_id[item].claim_id,
                        )
                        for item in cell.supporting_justification_ids
                    ),
                    tuple(
                        (
                            justifications_by_id[item].rule.value,
                            justifications_by_id[item].claim_id,
                        )
                        for item in cell.refuting_justification_ids
                    ),
                    tuple(
                        (
                            row.outcome.value,
                            (row.source_site.owner.anchor_ea,
                             row.source_site.instruction_ea),
                            None if row.projected_site is None else
                            (row.projected_site.owner.anchor_ea,
                             row.projected_site.instruction_ea),
                            row.relation_id,
                            row.supporting_claim_id,
                        )
                        for row in sealed_rows
                    ),
                    tuple(
                        (row.preserved, row.effect_kind.value, row.instruction_ea)
                        for row in effect_evidence
                    ),
                    tuple(
                        (row.owner_serial, row.owner_anchor_ea,
                         row.instruction_ea, row.effect_kind.value)
                        for row in source_effects
                    ),
                    tuple(
                        (row.owner_serial, row.owner_anchor_ea,
                         row.instruction_ea, row.effect_kind.value,
                         row.owner_serial
                         in inputs.candidate_inventory.reachable_serials)
                        for row in candidate_effects
                    ),
                    tuple(
                        (
                            row.owner_serial in raw_effect.pre_effectful_block_serials,
                            row.owner_serial in raw_effect.lost_block_serials,
                        )
                        for row in source_effects
                    ),
                    tuple(
                        (
                            row.owner_serial in effective_effect.pre_effectful_block_serials,
                            row.owner_serial in effective_effect.lost_block_serials,
                            row.owner_serial
                            in effective_effect.post_reachable_effectful_block_serials,
                        )
                        for row in source_effects
                    ),
                )
        if _timings is not None:
            _timings.evaluation_ms = _elapsed_ms(evaluation_started_ns, perf_counter_ns())
        # Mint the exhaustive classification even for a rejected semantic
        # case.  Rejection must be attributable to the same loss ledger every
        # projected gate would consume on success; it must not disappear back
        # into a binder-only error before the transaction can explain it.
        projected_loss_ledger = build_projected_semantic_loss_ledger(case, verdict)
        verdict = replace(verdict, loss_ledger=projected_loss_ledger)
        if verdict.accepted:
            if projected_loss_ledger.unclassified or projected_loss_ledger.conflicting:
                logger.warning(
                    "accepted projected case produced noncanonical loss rows: %r",
                    tuple(
                        (
                            row.source_subject.anchor_ea,
                            row.source_subject.block_ref,
                            row.kind.value,
                            row.structural_obligation.state.value,
                            tuple(
                                (
                                    cell.key.dimension.value,
                                    cell.key.subject.anchor_ea,
                                    cell.state.value,
                                )
                                for cell in row.relevant_semantic_obligations
                            ),
                            tuple(item.rule.value for item in row.justifications),
                        )
                        for row in (
                            *projected_loss_ledger.unclassified,
                            *projected_loss_ledger.conflicting,
                        )
                    ),
                )
            # Mint exactly once, then make every applicable projected gate
            # consume the same immutable occurrence.  Generic CFG facts were
            # inputs to canonical classification above; they are not a second
            # acceptance authority after this point.
            gates.validate_projected_loss_ledger(projected_loss_ledger, case)
            prepared = model.PreparedUnflattenAuthority(
                authority_id=prepared_authority_id, route=route.route,
                owning_plan=plan, proposal=proposal, claims=inputs.claims,
                source_route_authority=source_route_authority,
                projected_route_realization=projected_route_realization,
                snapshot_id=plan.snapshot_id,
                source_maturity=plan.source_maturity,
                source_coordinate_digest=authority_id(
                    model._canonical_source_coordinates(plan.source_coordinates)
                ),
                source_fingerprint=inputs.source_inventory.graph_fingerprint,
                projected_fingerprint=inputs.candidate_inventory.graph_fingerprint,
                source_generation=inputs.source_inventory.generation,
                projected_generation=inputs.candidate_inventory.generation,
                source_bindings=inputs.source_inventory.bindings,
                projected_bindings=inputs.candidate_inventory.bindings,
                projected_case=case,
                projected_loss_ledger=projected_loss_ledger,
                source_inputs=inputs,
                source_inventory=source_inventory,
                preparation_attempt_id=attempt_id,
                entry_endpoint_liveness_receipts=entry_liveness_receipts,
            )
            return UnflattenAuthorityPreparationAccepted(
                prepared, verdict,
                route_authority_verification=route_authority_verification,
            )
        # The canonical verdict is already rejecting.  Revalidate the same
        # exhaustive ledger once for diagnostics; no dimension-specific gate
        # owns a second loss model or replays the classification.
        try:
            gates.validate_projected_loss_ledger(projected_loss_ledger, case)
        except ValueError:
            pass
        return UnflattenAuthorityPreparationRejected(
            verdict,
            route_authority_verification=route_authority_verification,
        )
    except (TypeError, ValueError) as error:
        logger.warning(
            "unflatten authority projected binding failed: %s: %s",
            type(error).__name__,
            error,
        )
        verdict = model.UnflattenAuthorityVerdict(
            False, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
            authority_id(proposal), None, None,
            candidate_fingerprint or _unavailable_candidate_fingerprint(plan.plan_id), None, (),
        )
        return UnflattenAuthorityPreparationRejected(
            verdict,
            route_authority_verification=route_authority_verification,
        )


def _prepare_unflatten_authority(*, source, projection, plan, attempt_id, generic_gates, _timings=None):
    """Run one complete projected preparation in its transaction-owned session."""

    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ):
        return _prepare_unflatten_authority_in_session(
            source=source, projection=projection, plan=plan,
            attempt_id=attempt_id, generic_gates=generic_gates, _timings=_timings,
        )


def prepare_unflatten_authority(*, source, projection, plan, attempt_id, generic_gates):
    return _prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt_id, generic_gates=generic_gates,
    )


def prepare_unflatten_authority_timed(
    *, source, projection, plan, attempt_id, generic_gates,
) -> TimedUnflattenAuthorityResult:
    recorder = _AuthorityTimingRecorder()
    result = _prepare_unflatten_authority(
        source=source, projection=projection, plan=plan,
        attempt_id=attempt_id, generic_gates=generic_gates,
        _timings=recorder,
    )
    return TimedUnflattenAuthorityResult(
        result,
        PhaseTimings(
            inventory_ms=recorder.inventory_ms,
            binding_ms=recorder.binding_ms,
            evaluation_ms=recorder.evaluation_ms,
            total_authority_ms=None,
        ),
    )


def revalidate_bound_patch_plan_against_prepared(
    prepared, bound_plan,
) -> BoundPatchPlan:
    """Recheck live plan authority before bind and observed consumption."""
    if type(prepared) is not model.PreparedUnflattenAuthority:
        raise TypeError("prepared must be PreparedUnflattenAuthority")
    if type(bound_plan) is not BoundPatchPlan:
        raise TypeError("bound_plan must be BoundPatchPlan")
    validate_bound_patch_plan(bound_plan)
    if prepared.source_inputs is None:
        raise ValueError("prepared authority lacks source inputs")
    if bound_plan.plan is not prepared.owning_plan:
        raise ValueError("bound patch plan belongs to a foreign plan")
    # Preparation sealed the complete claim/lineage inventory.  Binding and
    # observation validate the exact prepared occurrence and exact plan
    # identity; they must never replay planner derivation to obtain equal DTOs.
    if bound_plan.plan.unflatten_proposal is not prepared.proposal:
        raise ValueError("bound patch plan proposal is not the prepared authority object")
    if prepared.preparation_attempt_id is None:
        raise ValueError("prepared authority has no exact preparation attempt")
    if bound_plan.attempt_id != prepared.preparation_attempt_id:
        raise ValueError("bound patch plan is from a different preparation attempt")
    if bound_plan.attempt_id.plan_id != prepared.proposal.plan_id:
        raise ValueError("bound patch plan attempt belongs to a foreign plan")
    if (
        bound_plan.session_id != bound_plan.attempt_id.session_id
        or bound_plan.generation != bound_plan.attempt_id.generation
    ):
        raise ValueError("bound patch plan session/generation differs from attempt")
    if (
        prepared.source_maturity is not None
        and prepared.source_maturity.provider_id is not None
        and bound_plan.maturity.provider_id != prepared.source_maturity.provider_id
    ):
        raise ValueError("bound patch plan maturity differs from source maturity")
    return bound_plan


def _observed_helper_serial_bindings(
    prepared: model.PreparedUnflattenAuthority,
    observed_binding: ObservedPatchBinding,
    observed: FlowGraph,
) -> dict[PlanBlockRef, int]:
    """Use the revalidated binder rows as the live helper-coordinate authority."""
    validate_observed_patch_binding(observed_binding)
    bound_plan = observed_binding.bound_plan
    rows = tuple(
        (ref, serial) for ref, serial in observed_binding.bindings
        if type(ref) is PlanBlockRef
    )
    if any(serial not in observed.blocks for _ref, serial in rows):
        raise ValueError("observed helper binding is absent from the live graph")
    if prepared.owning_plan.plan_id != bound_plan.plan.plan_id:
        raise ValueError("observed helper binding belongs to a foreign plan")
    if prepared.projected_generation != bound_plan.generation:
        raise ValueError("observed helper binding generation differs from authority")
    return dict(rows)


def bind_entry_endpoint_liveness_allowances(
    *,
    plan: PatchPlan,
    allowances: tuple[model.EntryEndpointLivenessAllowance, ...],
    patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
    source: FlowGraph,
    projected: FlowGraph,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
) -> tuple[model.BoundEntryEndpointLivenessAllowance, ...]:
    """Mint the one transaction receipt for each no-provider live-safe entry.

    This is intentionally separate from semantic-route realization: an entry
    endpoint shortcut is justified by planner liveness and its own redirect
    preimage, not by a fabricated equivalent-route claim.
    """
    if type(plan) is not PatchPlan or type(allowances) is not tuple or type(patch_step_facts) is not tuple:
        raise TypeError("entry liveness binding requires closed plan, allowances, and facts")
    if type(source) is not FlowGraph or type(projected) is not FlowGraph:
        raise TypeError("entry liveness binding requires source and projected FlowGraphs")
    if type(source_inventory) is not model.SemanticGraphInventory or type(projected_inventory) is not model.SemanticGraphInventory:
        raise TypeError("entry liveness binding requires exact source and projected inventories")
    if plan.unflatten_proposal is None:
        raise ValueError("entry liveness binding requires typed proposal")
    proposal = plan.unflatten_proposal
    if set(allowances) != set(proposal.entry_endpoint_liveness_allowances):
        raise ValueError("entry liveness binding allowances differ from proposal")
    if source_inventory.graph_fingerprint != semantic_graph_fingerprint(source):
        raise ValueError("entry liveness source inventory fingerprint drifted")
    if projected_inventory.graph_fingerprint != semantic_graph_fingerprint(projected):
        raise ValueError("entry liveness projected inventory fingerprint drifted")
    if source_inventory.generation != plan.source_generation:
        raise ValueError("entry liveness source inventory generation drifted")
    if (
        source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
        or projected_inventory.phase
        is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    ):
        raise ValueError("entry liveness inventories have invalid authority phases")
    facts_by_index = {fact.step_index: fact for fact in patch_step_facts}
    if len(facts_by_index) != len(patch_step_facts):
        raise ValueError("entry liveness patch facts must have unique step indices")
    proof_by_id = {proof.proof_id: proof for proof in proposal.route_evidence.route_proofs}
    selected_route_proof_ids = {
        proof_id
        for claim in proposal.claims
        if type(claim) is model.EquivalentSemanticRouteClaim
        for proof_id in claim.route_proof_ids
    }
    source_witnesses = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    serials = dict(plan.source_coordinates)
    source_serials_by_ref = dict(source_inventory.serial_by_ref)
    refs_by_serial = {serial: ref for ref, serial in plan.source_coordinates}
    scopes: set[tuple[object, ...]] = set()
    result: list[model.BoundEntryEndpointLivenessAllowance] = []
    for allowance in allowances:
        if type(allowance) is not model.EntryEndpointLivenessAllowance:
            raise TypeError("entry liveness allowance has an unknown type")
        allowance.__post_init__()
        proof = proof_by_id.get(allowance.route_proof_id)
        if proof is None or type(allowance.replacement_endpoint_ref) is not NativeBlockRef:
            raise ValueError("entry liveness allowance route proof or destination is foreign")
        rejection_detail = _entry_liveness_route_proof_rejection_detail(
            source_witnesses=source_witnesses,
            replacement_ref=allowance.replacement_endpoint_ref,
            redirect_owner_ref=allowance.entry_predecessor_owner_refs[0],
            dispatcher_old_target_ref=allowance.dispatcher_old_target_ref,
            state_production_source_ref=allowance.state_write_source_ref,
            state_production_instruction_ea=allowance.state_write_instruction_ea,
            route_proof_id=allowance.route_proof_id,
            selected_ids=selected_route_proof_ids,
            proof=proof,
            state_identity=proposal.plan_inputs.state_identity,
            normalized_state=allowance.normalized_state,
        )
        if rejection_detail is not None:
            raise ValueError("entry liveness allowance does not name one exact canonical route")
        scope = (
            allowance.patch_step_index, allowance.entry_predecessor_owner_refs,
            allowance.dispatcher_old_target_ref, allowance.replacement_endpoint_ref,
        )
        if scope in scopes:
            raise ValueError("entry liveness allowances overlap one exact redirect scope")
        scopes.add(scope)
        fact = facts_by_index.get(allowance.patch_step_index)
        if fact is None:
            raise ValueError("entry liveness allowance patch fact is absent")
        if fact.plan_id != plan.plan_id or fact.step_digest != allowance.patch_step_digest:
            raise ValueError("entry liveness allowance step digest drifted")
        descriptor = canonical_patch_step_descriptor(plan, allowance.patch_step_index)
        if descriptor.step_digest != allowance.patch_step_digest:
            raise ValueError("entry liveness allowance descriptor digest drifted")
        if descriptor.step_type not in {"PatchRedirectGoto", "PatchRedirectBranch"}:
            raise ValueError("entry liveness allowance requires an exact redirect step")
        step = plan.steps[allowance.patch_step_index]
        if (
            descriptor.owner_refs != allowance.entry_predecessor_owner_refs
            or descriptor.route_refs[:3] != (
                allowance.entry_predecessor_owner_refs[0],
                allowance.dispatcher_old_target_ref,
                allowance.replacement_endpoint_ref,
            )
            or fact.owner_ref != allowance.entry_predecessor_owner_refs[0]
            or getattr(step, "old_target", None) != allowance.dispatcher_old_target_ref
            or getattr(step, "new_target", None) != allowance.replacement_endpoint_ref
        ):
            raise ValueError("entry liveness allowance redirect coordinates drifted")
        owner_serial = serials.get(fact.owner_ref)
        old_serial = serials.get(allowance.dispatcher_old_target_ref)
        new_serial = serials.get(allowance.replacement_endpoint_ref)
        # Only redirect coordinates must be patch-plan coordinates.  The write
        # and its delivery/exit path are source evidence and bind through the
        # complete source inventory instead.
        write_serial = source_serials_by_ref.get(allowance.state_write_source_ref)
        exit_serials = tuple(
            source_serials_by_ref.get(ref) for ref in allowance.exit_path_refs
        )
        delivery_serials = tuple(
            source_serials_by_ref.get(ref) for ref in allowance.delivery_path_refs
        )
        if None in (owner_serial, old_serial, new_serial) or any(value is None for value in exit_serials):
            raise ValueError("entry liveness allowance source coordinates drifted")
        if write_serial is None or any(value is None for value in delivery_serials):
            raise ValueError("entry liveness allowance immutable source evidence drifted")
        if (
            allowance.entry_predecessor_owner_refs[0]
            != allowance.state_write_source_ref
            and not delivery_serials
        ):
            raise ValueError(
                "entry liveness distinct owner requires a delivery corridor"
            )
        if delivery_serials:
            if (
                int(delivery_serials[0]) != int(write_serial)
                or int(delivery_serials[-1]) != int(old_serial)
                or int(delivery_serials[-2]) != int(owner_serial)
                or tuple(
                    (int(delivery_serials[left]), int(delivery_serials[right]))
                    for left, right in allowance.delivery_path_edges
                )
                != tuple(zip(delivery_serials, delivery_serials[1:]))
                or any(
                    int(right) not in source.blocks[int(left)].succs
                    for left, right in zip(delivery_serials, delivery_serials[1:])
                )
            ):
                raise ValueError("entry liveness allowance delivery corridor drifted")
        owner = source.get_block(int(owner_serial))
        if owner is None:
            raise ValueError("entry liveness source owner is absent")
        source_successors = tuple(refs_by_serial.get(serial) for serial in owner.succs)
        if any(ref is None for ref in source_successors) or int(old_serial) not in owner.succs:
            raise ValueError("entry liveness source redirect preimage drifted")
        state = proposal.plan_inputs.state_identity
        state_stkoff = state.offset if state.kind is StorageIdentityKind.STACK else None
        if exit_path_blocks_live_violations(
            source, tuple(exit_serials), int(new_serial), state_stkoff,
            source_blocks=(int(owner_serial),), old_target=int(old_serial),
            cut_exit_path_uses=allowance.cut_exit_path_uses,
        ):
            raise ValueError("entry liveness allowance is no longer live-safe")
        projected_owner = projected.get_block(int(owner_serial))
        if projected_owner is None or int(new_serial) not in projected_owner.succs or int(old_serial) in projected_owner.succs:
            raise ValueError("entry liveness allowance projected redirect is not realized")
        projected_successors = tuple(refs_by_serial.get(serial) for serial in projected_owner.succs)
        if any(ref is None for ref in projected_successors):
            raise ValueError("entry liveness projected successor coordinate drifted")
        # The receipt model seals successor coordinates as a canonical ref
        # tuple.  Hash the same representation here: branch successor order
        # is physical CFG layout, not receipt authority.
        source_successor_refs = model._canonical_cfg_ref_tuple(
            tuple(source_successors), "source_owner_successors",
        )
        projected_successor_refs = model._canonical_cfg_ref_tuple(
            tuple(projected_successors), "projected_owner_successors",
        )
        binding_id = authority_id((
            "unflatten.entry-endpoint-liveness-binding.v1", allowance,
            allowance.route_proof_id, fact,
            source_inventory.graph_fingerprint, projected_inventory.graph_fingerprint,
            source_inventory.generation, projected_inventory.generation,
            source_inventory.inventory_digest, projected_inventory.inventory_digest,
            source_successor_refs, projected_successor_refs,
            True, True,
        ))
        receipt = model.BoundEntryEndpointLivenessAllowance(
            binding_id, allowance, allowance.route_proof_id, fact,
            source_inventory.graph_fingerprint, projected_inventory.graph_fingerprint,
            source_inventory.generation, projected_inventory.generation,
            source_inventory.inventory_digest, projected_inventory.inventory_digest,
            source_successor_refs, projected_successor_refs,
            True, True,
        )
        result.append(receipt)
    # Do not expose a partially validated receipt set when a later allowance
    # fails.  Occurrence publication is the final action of this complete
    # transaction binding path, deliberately co-located with its validation.
    ordered = tuple(sorted(result, key=lambda item: item.binding_id))
    return authority_bind._publish_bound_entry_endpoint_liveness_batch(ordered)


def _admit_bound_entry_endpoint_liveness(
    *,
    proposal: model.ProposedUnflattenContract,
    receipts: tuple[model.BoundEntryEndpointLivenessAllowance, ...],
    patch_step_facts: tuple[model.PatchStepEvidencePayload, ...],
) -> tuple[model.BoundEntryEndpointLivenessAllowance, ...]:
    """Close semantic admission over transaction-minted receipts only."""
    if type(receipts) is not tuple or type(patch_step_facts) is not tuple:
        raise TypeError("entry liveness admission requires closed receipts and facts")
    if {item.allowance for item in receipts} != set(proposal.entry_endpoint_liveness_allowances):
        raise ValueError("entry liveness admission requires an exact allowance receipt bijection")
    facts = {(item.step_index, item.step_digest): item for item in patch_step_facts}
    if len(facts) != len(patch_step_facts):
        raise ValueError("entry liveness admission patch facts are ambiguous")
    for receipt in receipts:
        if type(receipt) is not model.BoundEntryEndpointLivenessAllowance:
            raise TypeError("entry liveness admission has an unknown receipt")
        authority_bind.validate_bound_entry_endpoint_liveness_allowance(receipt)
        fact = facts.get((receipt.allowance.patch_step_index, receipt.allowance.patch_step_digest))
        if fact is not receipt.patch_step_fact:
            raise ValueError("entry liveness admission receipt fact is foreign")
    receipt_ids = tuple(item.binding_id for item in receipts)
    if receipt_ids != tuple(sorted(receipt_ids)) or len(set(receipt_ids)) != len(receipt_ids):
        raise ValueError("entry liveness admission receipts are not canonical")
    return receipts


def bind_prepared_unflatten_authority(*, prepared, patch_binding):
    """Bind prepared authority to the exact result of ``bind_patch_plan``."""
    from .model import UnflattenAuthorityBindingAccepted, UnflattenAuthorityBindingRejected
    if type(prepared) is not model.PreparedUnflattenAuthority:
        raise TypeError("prepared must be PreparedUnflattenAuthority")
    try:
        if type(patch_binding) is not BoundPatchPlan:
            raise TypeError("patch_binding must be BoundPatchPlan")
        revalidate_bound_patch_plan_against_prepared(prepared, patch_binding)
        ident = bound_unflatten_binding_id(prepared, patch_binding)
        authority = model.BoundUnflattenAuthority(
            binding_id=ident, prepared=prepared, attempt_id=patch_binding.attempt_id,
            session_id=patch_binding.session_id, generation=patch_binding.generation,
            live_maturity=patch_binding.maturity, live_bindings=patch_binding.bindings,
            patch_binding=patch_binding,
            entry_endpoint_liveness_receipts=prepared.entry_endpoint_liveness_receipts,
        )
        return UnflattenAuthorityBindingAccepted(authority)
    except (TypeError, ValueError):
        verdict = model.UnflattenAuthorityVerdict(
            False, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
            prepared.authority_id, None, None, prepared.projected_fingerprint, None, (),
        )
        return UnflattenAuthorityBindingRejected(verdict)


def validate_observed_commit_authority(authority, verdict, accepted) -> None:
    """Reject any tampered observed authority before the mutation receipt closes."""
    if type(authority) is not model.BoundUnflattenAuthority:
        raise TypeError("commit requires BoundUnflattenAuthority")
    if type(verdict) is not model.UnflattenAuthorityVerdict:
        raise TypeError("commit requires UnflattenAuthorityVerdict")
    if type(accepted) is not model.ObservedUnflattenAuthorityAccepted:
        raise TypeError("commit requires ObservedUnflattenAuthorityAccepted")
    # Bound authority validation already revalidates its exact nested
    # binding.  Validate the preparation's own scalar/identity relations once,
    # but its child cases and ledgers remain exact sealed occurrences and are
    # not recursively replayed here.
    model.BoundUnflattenAuthority.__post_init__(authority)
    model.PreparedUnflattenAuthority.__post_init__(authority.prepared)
    model.ObservedUnflattenAuthorityAccepted.__post_init__(accepted)
    model.ObservedSemanticLossDelta.__post_init__(accepted.delta)
    model.UnflattenAuthorityVerdict.__post_init__(verdict)
    if verdict.observed_acceptance is not accepted:
        raise ValueError("commit observed acceptance differs from verdict")
    if accepted.bound_authority is not authority:
        raise ValueError("commit observed authority differs from bound authority")
    if (
        not verdict.accepted
        or verdict.phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
        or verdict.safety_case is not accepted.observed_case
        or verdict.case_id != accepted.observed_case.case_id
        or verdict.authority_id != authority.prepared.authority_id
        or verdict.binding_id != authority.binding_id
    ):
        raise ValueError("commit observed verdict does not close the exact authority")
    if (
        accepted.projected_ledger is not authority.prepared.projected_loss_ledger
        or accepted.projected_ledger.case is not authority.prepared.projected_case
        or accepted.observed_ledger.case is not accepted.observed_case
    ):
        raise ValueError("commit observed ledgers do not close exact authority cases")


def _log_first_observed_authority_mismatch(
    verdict: model.UnflattenAuthorityVerdict,
) -> None:
    """Project the first sealed failed obligation into a bounded diagnostic.

    Diagnostics traverse the evaluator-owned obligation graph.  They never
    replay owner precedence, identity matching, or topology classification.
    """

    if type(verdict) is not model.UnflattenAuthorityVerdict:
        return
    case = verdict.safety_case
    if type(case) is not model.SemanticSafetyCase:
        return

    def subject_coordinate(subject: model.SemanticSubjectRef) -> str:
        """Render a bounded stable coordinate, never a full native identity."""
        anchor = subject.anchor_ea
        anchor_text = "none" if anchor is None else f"0x{anchor:X}"
        return f"{subject.role.value}@{anchor_text}#{subject.subject_id[7:19]}"

    def relation_coordinates(relations) -> tuple[str, ...]:
        return tuple(
            f"{relation.source_subject_id[7:15]}->{relation.target_subject_id[7:15]}"
            f"@0x{relation.native_edge_anchor_ea:X}"
            for relation in relations[:8]
        )

    if verdict.failed_obligations:
        failure = verdict.failed_obligations[0]
        cell = next(
            (
                item
                for item in case.obligation_index.cells
                if item.key == failure.key
            ),
            None,
        )
        justification_by_id = {
            item.justification_id: item for item in case.justifications
        }
        evidence_by_id = {item.evidence_id: item for item in case.evidence}
        justification_ids = (
            ()
            if cell is None
            else (
                *cell.refuting_justification_ids,
                *cell.supporting_justification_ids,
            )
        )
        justifications = tuple(
            justification_by_id[item]
            for item in justification_ids[:8]
            if item in justification_by_id
        )
        premises = []
        for justification in justifications:
            for premise_id in justification.premise_ids:
                premise = evidence_by_id.get(premise_id)
                if premise is None:
                    continue
                detail = premise.kind.value
                if type(premise.payload) is model.PhaseBindingEvidencePayload:
                    binding = premise.payload.binding
                    serial = (
                        "none" if binding.serial is None else f"blk{binding.serial}"
                    )
                    detail = (
                        f"{detail}:{subject_coordinate(premise.subject)}:"
                        f"{binding.status.value}:{serial}"
                    )
                premises.append(detail)
                if len(premises) == 8:
                    break
            if len(premises) == 8:
                break
        logger.warning(
            "observed authority first failure dimension=%s state=%s subject=%s "
            "rules=%s premises=%s",
            failure.key.dimension.value,
            failure.state.value,
            subject_coordinate(failure.key.subject),
            tuple(item.rule.value for item in justifications),
            tuple(premises),
        )

    for item in case.evidence:
        payload = item.payload
        if type(payload) is not model.TopologyEvidencePayload:
            continue
        if (
            payload.expected_shape_digest
            == payload.candidate_shape_digest
        ):
            continue
        logger.warning(
            "observed authority topology mismatch subject=%s expected_digest=%s "
            "candidate_digest=%s expected=%s candidate=%s",
            subject_coordinate(item.subject),
            payload.expected_shape_digest[7:19],
            payload.candidate_shape_digest[7:19],
            relation_coordinates(payload.expected_edge_relations),
            relation_coordinates(payload.candidate_edge_relations),
        )
        break

    for item in case.evidence:
        if (
            item.subject.role
            is not model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
            or type(item.payload) is not model.PhaseBindingEvidencePayload
        ):
            continue
        binding = item.payload.binding
        owner_refs = getattr(item.subject.locator, "redirect_owner_refs", ())
        owner_binding_rows = tuple(
            (
                evidence.subject.block_ref,
                subject_coordinate(evidence.subject),
                evidence.payload.binding.status.value,
                evidence.payload.binding.serial,
            )
            for evidence in case.evidence
            if type(evidence.payload) is model.PhaseBindingEvidencePayload
            and evidence.subject.block_ref in owner_refs
        )
        owner_bindings = tuple(row[1:] for row in owner_binding_rows)
        owner_failures = tuple(
            row[1:] for row in owner_binding_rows
            if row[2] != model.SubjectBindingStatus.UNIQUE.value
        )
        represented_refs = {row[0] for row in owner_binding_rows}
        unrepresented_refs = tuple(
            subject_coordinate(subject)
            for ref in owner_refs
            if ref not in represented_refs
            for subject in case.source_inventory.subjects
            if subject.block_ref == ref
        )
        logger.warning(
            "observed authority value-flow binding subject=%s status=%s serial=%s "
            "owner_count=%d owner_failures=%s unrepresented=%s owner_bindings=%s",
            subject_coordinate(item.subject),
            binding.status.value,
            binding.serial,
            len(owner_refs),
            owner_failures,
            unrepresented_refs,
            owner_bindings[:16],
        )
        break


def _revalidate_observed_unflatten_authority_in_session(
    *, authority, observed, observed_generation, generic_gates,
    observed_patch_binding, _timings=None,
):
    """Revalidate a bound authority against the observed graph identity."""
    if type(authority) is not model.BoundUnflattenAuthority:
        return _observed_live_binding_failure(
            "authority_type",
            TypeError(
                "expected BoundUnflattenAuthority, got "
                f"{type(authority).__name__}"
            ),
        )
    if type(observed) is not FlowGraph:
        raise TypeError("observed must be FlowGraph")
    if type(observed_generation) is not int or observed_generation < 0:
        return model.UnflattenAuthorityVerdict(
            False,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            model.UnflattenAuthorityReason.GRAPH_GENERATION_MISMATCH,
            None,
            None,
            None,
            _unavailable_candidate_fingerprint("observed-generation"),
            None,
            (),
        )
    binding_started_ns = perf_counter_ns()
    try:
        # This transitively revalidates the exact nested preparation once.
        model.BoundUnflattenAuthority.__post_init__(authority)
    except (TypeError, ValueError, AttributeError) as error:
        return _observed_live_binding_failure("bound_authority_validation", error)
    try:
        revalidate_bound_patch_plan_against_prepared(
            authority.prepared, authority.patch_binding
        )
    except (TypeError, ValueError, AttributeError) as error:
        return _observed_live_binding_failure("bound_patch_plan_validation", error)
    try:
        if type(observed_patch_binding) is not ObservedPatchBinding:
            raise TypeError("observed validation requires ObservedPatchBinding")
        validate_observed_patch_binding(observed_patch_binding)
        if observed_patch_binding.bound_plan is not authority.patch_binding:
            raise ValueError(
                "observed patch binding differs from exact bound authority"
            )
        observed_helper_serials = _observed_helper_serial_bindings(
            authority.prepared, observed_patch_binding, observed,
        )
    except (TypeError, ValueError, AttributeError) as error:
        return _observed_live_binding_failure("observed_helper_bindings", error)
    pre_inventory_binding_ms = _elapsed_ms(binding_started_ns, perf_counter_ns())
    validated_prepared = authority.prepared
    validated_generation = authority.generation
    if observed_generation != validated_generation:
        return model.UnflattenAuthorityVerdict(
            False,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            model.UnflattenAuthorityReason.GRAPH_GENERATION_MISMATCH,
            validated_prepared.authority_id,
            authority.binding_id,
            None,
            _unavailable_candidate_fingerprint("observed-generation-mismatch"),
            None,
            (),
        )
    inventory_started_ns = perf_counter_ns()
    try:
        # The same seam, for the observed session.  It is a *different*
        # session and therefore a different arena, so the observed phase mints
        # its own references and can never mistake a projected ordinal for an
        # observed one.  It gets its own provenance label: a refusal here is a
        # route-authority rebind failure, and reporting it as an inventory
        # failure would send a reader to the wrong stage.
        observed_route_authority_verification = _record_route_authority_rebind(
            validated_prepared.proposal.route_evidence,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        )
    except (TypeError, ValueError) as error:
        return _observed_live_binding_failure(
            "observed_route_authority_rebind", error,
            authority_id_value=validated_prepared.authority_id,
            binding_id_value=authority.binding_id,
            candidate_fingerprint=_unavailable_candidate_fingerprint(
                "observed-route-authority-rebind"
            ),
        )
    try:
        observed_materialization = capture_observed_route_materialization(
            observed, generation=observed_generation,
        )
        candidate_inventory = _build_semantic_graph_inventory(
            observed, validated_prepared.proposal, validated_prepared.owning_plan,
            source=False, phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=validated_prepared.source_inventory.subjects,
            source_inventory=validated_prepared.source_inventory,
            materialization=observed_materialization,
            planned_serials=observed_helper_serials,
            observed_patch_binding=observed_patch_binding,
            prepared_authority=validated_prepared,
        )
    except (TypeError, ValueError) as error:
        return _observed_live_binding_failure(
            "observed_inventory", error,
            authority_id_value=validated_prepared.authority_id,
            binding_id_value=authority.binding_id,
            candidate_fingerprint=_unavailable_candidate_fingerprint(
                "observed-inventory"
            ),
            route_authority_verification=observed_route_authority_verification,
        )
    inventory_ms = _elapsed_ms(inventory_started_ns, perf_counter_ns())
    phase_build_metrics = model.PhaseBuildMetrics(
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1,
        inventory_ms,
    )
    if _timings is not None:
        _timings.inventory_ms = inventory_ms
    post_inventory_binding_started_ns = perf_counter_ns()
    observed_fingerprint = candidate_inventory.graph_fingerprint
    prepared_inputs = validated_prepared.source_inputs
    if prepared_inputs is None:
        raise ValueError("prepared authority lacks its closed source inventory")
    if validated_prepared.source_inventory is not prepared_inputs.source_inventory:
        raise ValueError("prepared source inventory identity changed")
    try:
        inputs = _derive_inputs(
            prepared_inputs.source_inventory, candidate_inventory,
            validated_prepared.owning_plan, validated_prepared.proposal, generic_gates,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            candidate_generation=observed_generation,
            phase_build_metrics=phase_build_metrics,
            preparation_metrics=prepared_inputs.preparation_metrics,
            source_route_authority=validated_prepared.source_route_authority,
            projected_route_realization=validated_prepared.projected_route_realization,
            preparation_inputs=prepared_inputs,
        )
        if _timings is not None:
            _timings.binding_ms = (
                pre_inventory_binding_ms
                + _elapsed_ms(post_inventory_binding_started_ns, perf_counter_ns())
            )
    except (TypeError, ValueError) as error:
        return _observed_live_binding_failure(
            "observed_input_derivation", error,
            authority_id_value=validated_prepared.authority_id,
            binding_id_value=authority.binding_id,
            candidate_fingerprint=observed_fingerprint,
            route_authority_verification=observed_route_authority_verification,
        )
    evaluation_started_ns = perf_counter_ns()
    observed_case = build_semantic_case(
        authority_id=validated_prepared.authority_id,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=inputs,
    )
    # The seam outcome rides the verdict from here on: the observed phase
    # returns nothing else, and every later ``replace`` carries the private
    # slot along, so a rejection carries it exactly like an acceptance.
    verdict = replace(
        evaluate_case(observed_case),
        binding_id=authority.binding_id,
        _route_authority_verification=observed_route_authority_verification,
    )
    observed_ledger = build_semantic_loss_ledger(observed_case, verdict)
    verdict = replace(verdict, loss_ledger=observed_ledger)
    projected_ledger = validated_prepared.projected_loss_ledger
    projected_subject_ids = {
        row.source_subject.subject_id for row in projected_ledger.rows
    }
    delta_rows = tuple(
        row for row in observed_ledger.rows
        if row.source_subject.subject_id not in projected_subject_ids
    )
    delta = model.ObservedSemanticLossDelta(
        authority_id=observed_case.authority_id,
        source_fingerprint=observed_case.source_fingerprint,
        projected_case_id=validated_prepared.projected_case.case_id,
        observed_case_id=observed_case.case_id,
        projected_ledger_id=projected_ledger.ledger_id,
        observed_ledger_id=observed_ledger.ledger_id,
        rows=delta_rows,
        delta_id=authority_id((
            "unflatten.observed-loss-delta.v1",
            projected_ledger.ledger_id,
            observed_ledger.ledger_id,
            tuple((
                row.source_subject.subject_id,
                tuple(kind.value for kind in row.classification_kinds),
                tuple(item.justification_id for item in row.justifications),
                tuple(item.evidence_id for item in row.evidence),
                tuple(item.claim_id for item in row.claims),
            ) for row in delta_rows),
        )),
    )
    if verdict.accepted:
        # The observed decisions consume this one occurrence, never raw sets.
        gates.validate_projected_loss_ledger(observed_ledger, observed_case)
        accepted = model.ObservedUnflattenAuthorityAccepted(
            authority, observed_patch_binding, projected_ledger,
            observed_case, observed_ledger, delta,
        )
        verdict = replace(verdict, observed_acceptance=accepted)
    else:
        _log_first_observed_authority_mismatch(verdict)
    if _timings is not None:
        _timings.evaluation_ms = _elapsed_ms(evaluation_started_ns, perf_counter_ns())
    return verdict


def _revalidate_observed_unflatten_authority(
    *, authority, observed, observed_generation, generic_gates,
    observed_patch_binding, _timings=None,
):
    """Run one observed revalidation in a fresh transaction-owned session."""

    with _canonical_validation_session(
        CanonicalSessionPhase.OBSERVED_REVALIDATION,
    ):
        return _revalidate_observed_unflatten_authority_in_session(
            authority=authority, observed=observed,
            observed_generation=observed_generation, generic_gates=generic_gates,
            observed_patch_binding=observed_patch_binding, _timings=_timings,
        )


def revalidate_observed_unflatten_authority(
    *, authority, observed, observed_generation, generic_gates,
    observed_patch_binding,
):
    return _revalidate_observed_unflatten_authority(
        authority=authority, observed=observed,
        observed_generation=observed_generation, generic_gates=generic_gates, observed_patch_binding=observed_patch_binding,
    )


def revalidate_observed_unflatten_authority_timed(
    *, authority, observed, observed_generation, generic_gates,
    observed_patch_binding,
) -> TimedUnflattenAuthorityResult:
    recorder = _AuthorityTimingRecorder()
    result = _revalidate_observed_unflatten_authority(
        authority=authority, observed=observed,
        observed_generation=observed_generation, generic_gates=generic_gates, observed_patch_binding=observed_patch_binding,
        _timings=recorder,
    )
    return TimedUnflattenAuthorityResult(
        result,
        PhaseTimings(
            inventory_ms=recorder.inventory_ms,
            binding_ms=recorder.binding_ms,
            evaluation_ms=recorder.evaluation_ms,
            total_authority_ms=None,
        ),
    )


def select_plan_route(plan: PatchPlan) -> PlanRouteResult:
    """Select the only valid authority route for ``plan``.

    Ordinary plans get a dedicated not-applicable result.  Every other route
    is explicit: a closed typed proposal is accepted, while legacy metadata
    requires an adapter and is never guessed as ordinary authority.
    """

    if type(plan) is not PatchPlan:
        raise TypeError("plan must be a PatchPlan")

    try:
        reserved_keys = reserved_metadata_keys(plan)
    except MetadataKeyTypeError:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "metadata_key_type_invalid",
        )
    except ValueError:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "metadata_shape_invalid",
        )
    proposal = plan.unflatten_proposal
    if proposal is not None:
        if reserved_keys:
            return RejectedPlanRoute(
                UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL,
                "typed_proposal_has_top_level_legacy_metadata",
                reserved_keys[0],
            )
        validation = validate_proposal(plan, proposal)
        if isinstance(validation, ProposalRejected):
            return RejectedPlanRoute(
                validation.reason,
                validation.detail_code,
                validation.key,
                validation.stage,
            )
        if not isinstance(validation, ProposalAccepted):
            raise TypeError("proposal validation returned an unknown result")
        return TypedProposalRoute(
            UnflattenPlanRoute.TYPED_PROPOSAL,
            validation.proposal,
        )

    if reserved_keys:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "legacy_metadata_requires_explicit_codec_adaptation",
            reserved_keys[0],
        )
    return UnflattenAuthorityNotApplicable(UnflattenPlanRoute.ORDINARY)
__all__ = [
    "select_plan_route",
    "prepare_unflatten_authority",
    "bind_prepared_unflatten_authority", "revalidate_observed_unflatten_authority",
        "TimedUnflattenAuthorityResult", "prepare_unflatten_authority_timed",
        "revalidate_observed_unflatten_authority_timed",
]
