"""Patch-transaction-facing route selection for unflatten authority."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from time import perf_counter
from time import perf_counter_ns
import hashlib
import re

from d810.transforms.plan import (
    PatchConditionalRedirect,
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
    capture_observed_route_materialization,
    capture_projected_route_materialization,
    capture_source_route_materialization,
)
from d810.ir.flowgraph import BlockKind, FlowGraph, InsnKind, OperandKind
from d810.ir.semantics import ControlTransferKind
from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
from d810.transforms.cfg_transaction import (
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
)
from d810.transforms.patch_binding import (
    BoundPatchPlan,
    iter_refs,
    validate_bound_patch_plan,
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
from .proposal import (
    CanonicalPatchStepDescriptor,
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


from d810.transforms.unflatten_authority.ids import (
    _claim_factory,
    _subject_factory,
    authority_id,
    bound_unflatten_binding_id,
    content_id,
    semantic_graph_inventory_digest,
    projected_authority_id,
)

from .model import (
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
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


def _live_binding_failed_verdict() -> model.UnflattenAuthorityVerdict:
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
    )


def _claim_subjects(claim):
    if type(claim) is model.RetiredDispatcherInfrastructureClaim:
        return (claim.infrastructure_subject, claim.corridor_subject, *claim.member_subjects)
    if type(claim) is model.DetachedDeadHandlerComponentClaim:
        return (claim.dispatcher_subject, *claim.dead_handler_subjects,
                *claim.retained_handler_subjects, *claim.component_subjects)
    if type(claim) is model.EquivalentSemanticRouteClaim:
        return (claim.retired_route_subject, claim.replacement_route_subject, claim.source_subject, *claim.destination_subjects)
    if type(claim) is model.ExactInfeasibleEffectClaim:
        return (claim.effect_subject, claim.source_subject, claim.predicate_subject, claim.selected_target_subject, claim.discarded_effect_subject)
    if type(claim) is model.LocalAliasEffectScalarizationClaim:
        return (claim.owner_subject,)
    if type(claim) is model.TerminalCycleBreakClaim:
        return (claim.cycle_subject, claim.cleanup_source_subject, claim.terminal_subject)
    raise TypeError("unsupported closed claim")


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
    for ref, serial in by_ref.items():
        if ref in expected:
            continue
        if not producer_api.is_unowned_structural_logical_stop(block_map[serial], ref):
            raise ValueError("plan source coordinates contain an unowned non-structural reference")
    # Keep only the exact logical function-exit coordinate in addition to the
    # native source catalog.  It is intentionally anchorless but source route
    # binding consumes its owned row to compare session/token/version for a
    # typed DAG leaf.  Ordinary synthetic STOP rows and arbitrary extra plan
    # coordinates remain unowned structural rows.
    return {
        ref: serial
        for ref, serial in by_ref.items()
        if ref in expected
        or producer_api.is_exact_logical_function_exit(block_map[serial], ref)
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


def _projected_serials(
    graph: FlowGraph, proposal, *, blocks=None, plan: PatchPlan | None = None,
    planned_serials: Mapping[PlanBlockRef, int] | None = None,
) -> dict[object, int]:
    result: dict[object, int] = {}
    block_values = graph.blocks if blocks is None else blocks
    catalog_by_ref = {
        witness.block_ref: witness
        for witness in proposal.source_identity_catalog.blocks
    }
    sealed_source_ref_by_serial = {
        int(serial): ref
        for ref, serial in (() if plan is None else plan.source_coordinates)
        if ref in catalog_by_ref
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
    return result


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


def _observed_native_identity_origins(
    block,
    *,
    owner_ref,
    serial_by_ref: Mapping[object, int],
    plan: PatchPlan,
    phase: model.UnflattenAuthorityPhase,
) -> int | None:
    """Exclude one plan-authorized generated redirect from native identity.

    A live backend can append a synthetic GOTO to a retained native block and
    assign it a valid-looking fallback EA.  That transfer remains part of the
    observed instruction/topology inventory, but it is not a source-native
    instruction origin.  This exception is deliberately exact: one native
    owner, one exact ``PatchRedirectGoto``, one tail GOTO, and its exact live
    target must all agree.  Every other additional origin stays in the row and
    is rejected by the normal native-identity invariant.
    """
    if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        return None
    if type(owner_ref) is not NativeBlockRef:
        return None
    if owner_ref not in dict(plan.source_coordinates):
        return None
    matching_steps = tuple(
        step for step in plan.steps
        if type(step) is PatchRedirectGoto and step.from_serial == owner_ref
    )
    if len(matching_steps) != 1:
        return None
    step = matching_steps[0]
    if serial_by_ref.get(step.new_target) is None:
        return None
    if (
        block.kind is not BlockKind.ONE_WAY
        or len(block.succs) != 1
        or block.succs[0] != serial_by_ref[step.new_target]
        or not block.insn_snapshots
    ):
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
            return None
        all_origins.append(origin)
    if all_origins.count(tail_origin) != 1:
        return None
    if tail_origin in owner_ref.identity.exact_instruction_eas:
        return None
    normalized_origins = tuple(sorted(set(all_origins) - {tail_origin}))
    if not set(normalized_origins) <= owner_ref.identity.exact_instruction_eas:
        return None
    return tail_origin


def _build_semantic_graph_inventory(
    graph: FlowGraph,
    proposal: model.ProposedUnflattenContract,
    plan: PatchPlan,
    *,
    source: bool,
    phase: model.UnflattenAuthorityPhase,
    source_subjects: tuple[model.SemanticSubjectRef, ...] = (),
    materialization: CanonicalRouteMaterialization | None = None,
    planned_serials: Mapping[PlanBlockRef, int] | None = None,
) -> model.SemanticGraphInventory:
    """Build one complete source or candidate inventory.

    This is the sole owner of serial projection, reachability, effect/terminal
    discovery, subject construction, and topology materialization.
    """

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
    reachable = _reachable_serials_from_blocks(blocks_by_serial, graph.entry_serial)
    serial_by_ref = (
        _catalog_serials(graph, proposal, plan, blocks=blocks_by_serial)
        if source else _projected_serials(
            graph, proposal, blocks=blocks_by_serial, plan=plan,
            planned_serials=planned_serials,
        )
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
        owner_anchor = None
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
                type(owner_ref) is LogicalBlockRef
                and type(owner_anchor) is int
                and owner_anchor == 0xFFFFFFFFFFFFFFFF
            ):
                owner_anchor = None
            if owner_anchor is None and type(owner_ref) is not LogicalBlockRef:
                raise ValueError("planned block has no exact native anchor")
        observed = producer_api.observe_inventory_block(
            block, owner_ref=owner_ref, owner_anchor_ea=owner_anchor,
        )
        synthetic_tail_origin = _observed_native_identity_origins(
            block,
            owner_ref=owner_ref,
            serial_by_ref=serial_by_ref,
            plan=plan,
            phase=phase,
        )
        if synthetic_tail_origin is not None:
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
        block_rows.append(observed)
        block_effects, block_terminals = model.resolve_inventory_block_sites(
            serial=observed.serial, owner_ref=observed.block_ref,
            owner_anchor_ea=observed.anchor_ea if observed.anchor_ea is not None else 0,
            block_kind=observed.block_kind,
            successor_serials=observed.successor_serials,
            instruction_observations=observed.instruction_observations,
        )
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
    bindings = (
        authority_bind.bind_subjects(
            subjects, catalog=proposal.source_identity_catalog,
            phase=phase, graph_fingerprint=fingerprint,
            generation=proposal.source_identity_catalog.generation,
            serial_by_ref=serial_by_ref,
        ) if source else authority_bind.bind_inventory_subjects(
            subjects, catalog=proposal.source_identity_catalog,
            phase=phase, graph_fingerprint=fingerprint,
            generation=proposal.source_identity_catalog.generation,
            serial_by_ref=serial_by_ref,
            effects=tuple(item for item in effects if item.owner_serial in reachable),
            terminals=tuple(item for item in terminals if item.owner_serial in reachable),
            reachable_serials=tuple(sorted(reachable)),
            native_instruction_eas_by_ref=(
                {
                    row.block_ref: row.native_instruction_eas
                    for row in block_rows
                    if row.block_ref is not None
                }
                if any(
                    isinstance(
                        step,
                        (
                            PatchRedirectBranch,
                            PatchLowerConditionalStateTransition,
                            PatchConditionalRedirect,
                            PatchEdgeSplitTrampoline,
                            PatchEdgeSplitCorridor,
                        ),
                    )
                    for step in plan.steps
                ) else None
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
    reachable_tuple = tuple(sorted(reachable))
    digest = semantic_graph_inventory_digest(
        phase, fingerprint, proposal.source_identity_catalog.generation,
        tuple(block_rows), subjects, bindings, effects, terminals, topology,
        reachable_tuple, graph.entry_serial, source_subject_ids, graph.func_ea,
    )
    return model.SemanticGraphInventory(
        phase, fingerprint, proposal.source_identity_catalog.generation,
        tuple(block_rows), subjects, bindings, effects, terminals, topology, digest,
        reachable_tuple,
        materialization.entry_serial,
        source_subject_ids,
        function_ea=graph.func_ea,
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
    tuple[model.ConditionalSubjectRelation, ...],
]:
    """Derive alias authority from the exact typed plan and source inventory."""

    if plan.source_generation is not None and plan.source_generation != source_inventory.generation:
        raise ValueError("local-alias plan generation differs from source inventory")

    claims: list[model.LocalAliasEffectScalarizationClaim] = []
    patch_facts: list[model.PatchStepEvidencePayload] = []
    occurrences: list[authority_bind._LocalAliasClaimFactOccurrence] = []
    relations: list[model.ConditionalSubjectRelation] = []
    source_coordinates = dict(plan.source_coordinates)
    blocks_by_serial = {block.serial: block for block in source_inventory.blocks}
    bindings_by_ref = {
        binding.block_ref: binding
        for binding in source_inventory.bindings
        if binding.block_ref is not None
        and binding.status is model.SubjectBindingStatus.UNIQUE
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
        binding = bindings_by_ref.get(step.block_serial)
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
        effects = tuple(
            item for item in source_inventory.effects
            if item.owner_serial == serial
            and item.instruction_ea == step.host_ea
            and item.opcode == step.host_opcode
            and item.effect_kind is model.EffectSiteKind.STORE
        )
        if len(observations) != 1 or len(effects) != 1:
            raise ValueError("local-alias step must identify one exact STORE observation")
        observation = observations[0]
        source_site = effects[0]
        if (
            observation.instruction_kind is not model.InsnKind.STORE
            or observation.ordinal != source_site.instruction_ordinal
            or observation.width != source_site.width
            or observation.raw_opcode is None
            or observation.is_call
            or observation.call_kind is not None
            or observation.control_transfer_kind is not None
            or block.block_ref != source_site.owner_ref
            or block.anchor_ea != source_site.owner_anchor_ea
        ):
            raise ValueError("local-alias step host is not a STORE")
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
        if step.value_size is not None and step.value_size != source_site.width:
            raise ValueError("local-alias step value size disagrees with STORE")
        step_digest = authority_id(_local_alias_step_preimage(step_index, step))
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
        patch_fact = model.PatchStepEvidencePayload(
            plan.plan_id, step_index, "PatchScalarizeLocalAliasAccess",
            step.block_serial, step_digest, step.host_ea, step.host_opcode,
            step.value_size,
        )
        patch_facts.append(patch_fact)
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
        tuple(sorted(relations, key=lambda item: (
            item.source_subject_id, item.target_subject_id,
            item.dimension.value, item.provenance_id,
        ))),
    )


def _derive_patch_lineage_facts(
    source_inventory: model.SemanticGraphInventory,
    plan: PatchPlan,
) -> tuple[model.PatchStepEvidencePayload, ...]:
    """Derive helper/resegmentation step evidence once at the transaction edge."""

    source_refs = set(source_inventory.serial_by_ref)
    route_refs = {
        subject.block_ref
        for claim in plan.unflatten_proposal.claims
        for subject in _claim_subjects(claim)
        if subject.block_ref is not None
    } if plan.unflatten_proposal is not None else set()
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
            if type(step) in {
                PatchConditionalRedirect, PatchLowerConditionalStateTransition,
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
        for owner in owners:
            if type(owner) is not PlanBlockRef and owner not in source_refs:
                raise ValueError("patch-step owner is foreign to the source or plan")
            if type(owner) is PlanBlockRef and owner.plan_id != plan.plan_id:
                raise ValueError("patch-step owner belongs to a foreign plan")
            helper_spec = helper_specs.get(owner) if type(owner) is PlanBlockRef else None
            if type(owner) is PlanBlockRef and helper_spec is None:
                raise ValueError("patch-step helper owner lacks exactly one creation spec")
            owner_preimage = ("owner", owner)
            for ref in refs:
                if ref is None:
                    continue
                if type(ref) is PlanBlockRef:
                    if ref.plan_id != plan.plan_id:
                        raise ValueError("patch-step reference belongs to a foreign plan")
                elif ref not in source_refs:
                    raise ValueError("patch-step reference is foreign to the source plan")
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
            if type(step) in {PatchLowerConditionalStateTransition, PatchRedirectGoto, PatchRedirectBranch} and route_refs and not {
                ref for ref in refs if ref is not None
            } <= route_refs | allowed_corridor_refs:
                raise ValueError("patch-step source and destination refs are outside proposal route subjects")
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

    alias_occurrences, alias_relations = (
        _derive_local_alias_transaction_facts(source_inventory, plan)
    )
    alias_claims = tuple(item.claim for item in alias_occurrences)
    alias_patch_facts = tuple(item.patch_step_fact for item in alias_occurrences)
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
    if corridor_result is not None and type(corridor_result) is not model.CorridorCoveragePhaseResult:
        raise TypeError("corridor_result must be CorridorCoveragePhaseResult or None")

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
    if phase is model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
        if type(preparation_inputs) is not model.DerivedUnflattenPreparationInputs:
            raise TypeError(
                "observed derivation requires transaction-owned preparation inputs"
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
        corridor_coverage_phase_result = (
            authority_bind.revalidate_observed_corridor_coverage(
                projected_result=preparation_inputs.corridor_coverage_phase_result,
                proposal=proposal,
                claims=claims,
                source_inventory=source_inventory,
                observed_inventory=candidate_inventory,
            )
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
        corridor_coverage_phase_result = authority_bind.bind_corridor_coverage_forecast(
            proposal=proposal,
            source_inventory=source_inventory,
            candidate_inventory=candidate_inventory,
            phase=phase,
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
    )


def _prepare_unflatten_authority(*, source, projection, plan, attempt_id, generic_gates, _timings=None):
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
            raise ValueError("source route authority binding rejected")
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
        )
        legacy_effective_comparison = _legacy_effective_gate_comparison_facts(
            generic_gate_facts.effectful_raw
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
        )
        realization_result = realize_projected_routes(
            authority_id_value=realization_authority_id,
            derived_claim_inventory=derived_claim_inventory,
            source_route_authority=source_route_authority,
            attempt_id=attempt_id,
            projected_inventory=candidate_inventory,
            raw_effect_gate_fact=raw_effect_gate_fact,
            legacy_effective_gate_facts=legacy_effective_comparison,
        )
        if type(realization_result) is not model.ProjectedRouteRealizationAccepted:
            raise ValueError(
                "projected route realization rejected: "
                f"failures={getattr(realization_result, 'failures', None)!r}"
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
        if _timings is not None:
            _timings.evaluation_ms = _elapsed_ms(evaluation_started_ns, perf_counter_ns())
        # Mint the exhaustive classification even for a rejected semantic
        # case.  Rejection must be attributable to the same loss ledger every
        # projected gate would consume on success; it must not disappear back
        # into a binder-only error before the transaction can explain it.
        projected_loss_ledger = build_projected_semantic_loss_ledger(case, verdict)
        verdict = replace(verdict, loss_ledger=projected_loss_ledger)
        if verdict.accepted:
            # Mint exactly once, then make every applicable projected gate
            # consume the same immutable occurrence.  Generic CFG facts were
            # inputs to canonical classification above; they are not a second
            # acceptance authority after this point.
            gates.validate_projected_effect_loss_ledger(projected_loss_ledger, case)
            gates.validate_projected_dispatcher_removal_ledger(projected_loss_ledger, case)
            gates.validate_projected_corridor_coverage_ledger(projected_loss_ledger, case)
            gates.validate_projected_terminal_loss_ledger(projected_loss_ledger, case)
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
            )
            return UnflattenAuthorityPreparationAccepted(prepared, verdict)
        # The canonical verdict is already rejecting.  Exercise every gate
        # against its exact ledger so no gate keeps an independent loss model;
        # their ValueErrors add no authority beyond that verdict.
        for projected_gate in (
            gates.validate_projected_effect_loss_ledger,
            gates.validate_projected_dispatcher_removal_ledger,
            gates.validate_projected_corridor_coverage_ledger,
            gates.validate_projected_terminal_loss_ledger,
        ):
            try:
                projected_gate(projected_loss_ledger, case)
            except ValueError:
                pass
        return UnflattenAuthorityPreparationRejected(verdict)
    except (TypeError, ValueError):
        verdict = model.UnflattenAuthorityVerdict(
            False, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
            authority_id(proposal), None, None,
            candidate_fingerprint or _unavailable_candidate_fingerprint(plan.plan_id), None, (),
        )
        return UnflattenAuthorityPreparationRejected(
            verdict,
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
    model.validate_semantic_graph_inventory(prepared.source_inventory)
    if prepared.source_inputs is None:
        raise ValueError("prepared authority lacks source inputs")
    model.DerivedUnflattenPreparationInputs.__post_init__(prepared.source_inputs)
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
    source_coordinates = dict(prepared.owning_plan.source_coordinates)
    discovered_refs = tuple(dict.fromkeys(iter_refs(
        (bound_plan.plan.steps, bound_plan.plan.new_blocks, bound_plan.plan.relocation_map),
    )))
    executable_refs = {
        ref for ref in discovered_refs
        if type(ref) in (NativeBlockRef, LogicalBlockRef)
    }
    helper_refs = {
        spec.block_id for spec in bound_plan.plan.new_blocks
    }
    supplied_refs = {ref for ref, _serial in bound_plan.bindings}
    if supplied_refs != executable_refs | helper_refs:
        raise ValueError("bound patch plan does not exactly cover executable references")
    expected_order = (
        tuple(ref for ref in discovered_refs if type(ref) in (NativeBlockRef, LogicalBlockRef))
        + tuple(spec.block_id for spec in bound_plan.plan.new_blocks)
    )
    if tuple(ref for ref, _serial in bound_plan.bindings) != expected_order:
        raise ValueError("bound patch plan reference order differs from live binder")
    if any(
        sum(1 for ref, _serial in bound_plan.bindings if ref == helper_ref) != 1
        for helper_ref in helper_refs
    ):
        raise ValueError("each PlanBlockRef helper requires exactly one bound row")
    for ref, serial in bound_plan.bindings:
        if type(ref) is PlanBlockRef:
            if ref not in helper_refs:
                raise ValueError("bound patch plan contains a foreign helper reference")
            continue
        if ref not in source_coordinates:
            raise ValueError("bound patch plan contains a foreign source reference")
        if int(source_coordinates[ref]) != int(serial):
            raise ValueError("bound patch plan source tuple differs from source coordinates")
    return bound_plan


def _observed_helper_serial_bindings(
    prepared: model.PreparedUnflattenAuthority,
    bound_plan: BoundPatchPlan,
    observed: FlowGraph,
) -> dict[PlanBlockRef, int]:
    """Use the revalidated binder rows as the live helper-coordinate authority."""
    helper_refs = tuple(spec.block_id for spec in bound_plan.plan.new_blocks)
    rows = tuple(
        (ref, serial) for ref, serial in bound_plan.bindings
        if type(ref) is PlanBlockRef
    )
    if tuple(ref for ref, _serial in rows) != helper_refs:
        raise ValueError("observed helper bindings do not exactly cover plan helpers")
    if len({serial for _ref, serial in rows}) != len(rows):
        raise ValueError("observed helper bindings duplicate live serials")
    source_serials = {
        serial for ref, serial in bound_plan.bindings
        if type(ref) in (NativeBlockRef, LogicalBlockRef)
    }
    source_serials.update(
        int(serial)
        for _ref, serial in prepared.owning_plan.source_coordinates
    )
    source_serials.update(
        int(binding.serial)
        for binding in prepared.source_inventory.bindings
        if binding.serial is not None
    )
    if any(serial in source_serials for _ref, serial in rows):
        raise ValueError("observed helper binding collides with a source serial")
    if any(serial not in observed.blocks for _ref, serial in rows):
        raise ValueError("observed helper binding is absent from the live graph")
    if prepared.owning_plan.plan_id != bound_plan.plan.plan_id:
        raise ValueError("observed helper binding belongs to a foreign plan")
    if prepared.projected_generation != bound_plan.generation:
        raise ValueError("observed helper binding generation differs from authority")
    return dict(rows)


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
    model.BoundUnflattenAuthority.__post_init__(authority)
    model.PreparedUnflattenAuthority.__post_init__(authority.prepared)
    model.ObservedUnflattenAuthorityAccepted.__post_init__(accepted)
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


def _revalidate_observed_unflatten_authority(
    *, authority, observed, observed_generation, generic_gates, _timings=None,
):
    """Revalidate a bound authority against the observed graph identity."""
    if type(authority) is not model.BoundUnflattenAuthority:
        return _live_binding_failed_verdict()
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
        model.BoundUnflattenAuthority.__post_init__(authority)
        model.PreparedUnflattenAuthority.__post_init__(authority.prepared)
        revalidate_bound_patch_plan_against_prepared(
            authority.prepared, authority.patch_binding
        )
        observed_helper_serials = _observed_helper_serial_bindings(
            authority.prepared, authority.patch_binding, observed,
        )
    except (TypeError, ValueError, AttributeError):
        return _live_binding_failed_verdict()
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
        observed_materialization = capture_observed_route_materialization(
            observed, generation=observed_generation,
        )
        candidate_inventory = _build_semantic_graph_inventory(
            observed, validated_prepared.proposal, validated_prepared.owning_plan,
            source=False, phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            source_subjects=validated_prepared.source_inventory.subjects,
            materialization=observed_materialization,
            planned_serials=observed_helper_serials,
        )
    except (TypeError, ValueError):
        return model.UnflattenAuthorityVerdict(
            False,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
            validated_prepared.authority_id,
            authority.binding_id,
            None,
            _unavailable_candidate_fingerprint("observed-inventory"),
            None,
            (),
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
    except (TypeError, ValueError):
        return model.UnflattenAuthorityVerdict(
            False,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
            validated_prepared.authority_id,
            authority.binding_id,
            None,
            observed_fingerprint,
            None,
            (),
        )
    evaluation_started_ns = perf_counter_ns()
    observed_case = build_semantic_case(
        authority_id=validated_prepared.authority_id,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        inputs=inputs,
    )
    verdict = replace(evaluate_case(observed_case), binding_id=authority.binding_id)
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
                row.source_subject.subject_id, row.kind.value,
                tuple(item.justification_id for item in row.justifications),
                tuple(item.evidence_id for item in row.evidence),
                tuple(item.claim_id for item in row.claims),
            ) for row in delta_rows),
        )),
    )
    if verdict.accepted:
        # The observed decisions consume this one occurrence, never raw sets.
        gates.validate_projected_effect_loss_ledger(observed_ledger, observed_case)
        gates.validate_projected_dispatcher_removal_ledger(observed_ledger, observed_case)
        gates.validate_projected_corridor_coverage_ledger(observed_ledger, observed_case)
        gates.validate_projected_terminal_loss_ledger(observed_ledger, observed_case)
        accepted = model.ObservedUnflattenAuthorityAccepted(
            authority, projected_ledger, observed_case, observed_ledger, delta,
        )
        verdict = replace(verdict, observed_acceptance=accepted)
    if _timings is not None:
        _timings.evaluation_ms = _elapsed_ms(evaluation_started_ns, perf_counter_ns())
    return verdict


def revalidate_observed_unflatten_authority(
    *, authority, observed, observed_generation, generic_gates,
):
    return _revalidate_observed_unflatten_authority(
        authority=authority, observed=observed,
        observed_generation=observed_generation, generic_gates=generic_gates,
    )


def revalidate_observed_unflatten_authority_timed(
    *, authority, observed, observed_generation, generic_gates,
) -> TimedUnflattenAuthorityResult:
    recorder = _AuthorityTimingRecorder()
    result = _revalidate_observed_unflatten_authority(
        authority=authority, observed=observed,
        observed_generation=observed_generation, generic_gates=generic_gates,
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
