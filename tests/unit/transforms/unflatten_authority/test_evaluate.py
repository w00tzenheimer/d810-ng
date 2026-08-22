"""Task 4 evaluator contract tests."""

from __future__ import annotations

import inspect
import json
from dataclasses import replace

import pytest

from d810.analyses.control_flow.semantic_route_evidence import BoundCanonicalSemanticEvidence
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticBlock
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticRoute
from d810.analyses.control_flow.semantic_route_evidence import BoundSemanticRouteDestination
from d810.ir.maturity import MaturityEnvelope
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.evaluate import build_semantic_case
from d810.transforms.unflatten_authority.evaluate import evaluate_case
from d810.transforms.unflatten_authority.evaluate import REQUIRED_DIMENSIONS
from d810.transforms.patch_binding import BoundPatchPlan
from d810.transforms.plan import PatchPlan
from d810.transforms.unflatten_authority.ids import _claim_factory, _evidence_factory, _justification_factory, _subject_factory, authority_id as canonical_authority_id, bound_unflatten_binding_id, canonical_bytes, canonical_decode, content_id, receipt_id, semantic_graph_inventory_digest
from .helpers import authority_id, block_ref, edge_role, state_identity
from .test_model import _valid_proposal


def _role_subject(role: model.SemanticSubjectRole, token: str) -> model.SemanticSubjectRef:
    if role in {
        model.SemanticSubjectRole.SOURCE_ENTRY,
        model.SemanticSubjectRole.DISPATCHER_ENTRY,
    }:
        ref = block_ref("b0")
    elif token.rsplit("-", 1)[-1].isdigit():
        ref = block_ref(f"b{int(token.rsplit('-', 1)[-1]) % 3}")
    else:
        ref = block_ref("b0")
    ref_anchor = {"b0": 0x1000, "b1": 0x1300, "b2": 0x1100}[ref.proxy_token]
    if role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER:
        kind, locator, owner, anchor = model.SemanticSubjectKind.HANDLER, model.HandlerSubjectLocator(ref, ref_anchor, (1,)), ref, ref_anchor
    elif role is model.SemanticSubjectRole.TERMINAL_SITE:
        kind, locator, owner, anchor = model.SemanticSubjectKind.TERMINAL, model.TerminalSubjectLocator(ref, ref_anchor, model.TerminalKind.RETURN, ref_anchor + 4), ref, ref_anchor
    elif role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
        kind, locator, owner, anchor = model.SemanticSubjectKind.VALUE_FLOW, model.ValueFlowSubjectLocator(authority_id("fragment"), state_identity(), (block_ref("b0"),)), None, None
    elif role is model.SemanticSubjectRole.DISPATCHER_CORRIDOR:
        kind, locator, owner, anchor = model.SemanticSubjectKind.CORRIDOR, model.CorridorSubjectLocator(authority_id(token), ref, ref_anchor, (ref,), (ref_anchor,)), ref, ref_anchor
    elif role is model.SemanticSubjectRole.EFFECT_SITE:
        kind, locator, owner, anchor = model.SemanticSubjectKind.EFFECT, model.EffectSubjectLocator(ref, ref_anchor, ref_anchor + 4, model.EffectSiteKind.STORE), ref, ref_anchor
    else:
        kind, locator, owner, anchor = model.SemanticSubjectKind.BLOCK, model.BlockSubjectLocator(ref, ref_anchor), ref, ref_anchor
    return _subject_factory(
        model.SemanticSubjectRef, kind=kind, role=role,
        block_ref=owner, anchor_ea=anchor, locator=locator,
    )


def test_route_payload_projects_destination_ids_in_locator_pair_order() -> None:
    """Destination IDs follow paired ref/EA order, not their hash order."""

    source = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "1")
    first = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "0")
    second = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    locator = model.RouteSubjectLocator(
        authority_id("route-order-proof"), authority_id("route-order-group"),
        source.block_ref, source.anchor_ea,
        (second.block_ref, first.block_ref),
        (second.anchor_ea, first.anchor_ea),
    )
    route = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=locator.source_ref,
        anchor_ea=locator.source_anchor_ea,
        locator=locator,
    )
    by_pair = {
        (first.block_ref, first.anchor_ea): first.subject_id,
        (second.block_ref, second.anchor_ea): second.subject_id,
    }
    payload = model.SemanticRouteEvidencePayload(
        route.subject_id,
        (locator.proof_id,),
        locator.atomic_group_id,
        source.subject_id,
        tuple(by_pair[pair] for pair in zip(locator.destination_refs, locator.destination_anchor_eas)),
        True,
    )
    assert payload.destination_subject_ids != tuple(sorted(by_pair.values()))
    assert canonical_decode(canonical_bytes(payload)) == payload


def _digest(value: object) -> str:
    return content_id("unflatten.authority.v1", value)


def _receipt_fixture(**kwargs: object) -> model.PreparationAuthorityReceipt:
    """Construct a complete receipt through the closed mint API."""
    return model.PreparationAuthorityReceipt.mint(**kwargs)


def _binding(subject: model.SemanticSubjectRef, phase: model.UnflattenAuthorityPhase, generation: int = 3, *, status: model.SubjectBindingStatus = model.SubjectBindingStatus.UNIQUE, fingerprint: str | None = None) -> model.PhaseSubjectBinding:
    if subject.block_ref is None:
        status = model.SubjectBindingStatus.MISSING
    serial_by_proxy = {"b0": 0, "b1": 1, "b2": 2}
    serial = serial_by_proxy.get(getattr(subject.block_ref, "proxy_token", ""), 0)
    return model.PhaseSubjectBinding(
        subject=subject, phase=phase, block_ref=subject.block_ref if status is model.SubjectBindingStatus.UNIQUE else None,
        graph_fingerprint=fingerprint or authority_id(f"graph-{phase.value}"), generation=generation, status=status,
        serial=serial if status is model.SubjectBindingStatus.UNIQUE else None,
        anchor_ea=subject.anchor_ea if status is model.SubjectBindingStatus.UNIQUE else None,
        native_instruction_eas=(subject.anchor_ea,) if status is model.SubjectBindingStatus.UNIQUE and subject.anchor_ea is not None else (), role=subject.role,
    )


def _complete_inputs(*, source_subjects: tuple[model.SemanticSubjectRef, ...], candidate_subjects: tuple[model.SemanticSubjectRef, ...] | None = None, source_bindings: tuple[model.PhaseSubjectBinding, ...] | None = None, candidate_bindings: tuple[model.PhaseSubjectBinding, ...] | None = None, lineage: tuple[model.AuthorityEvidence, ...] = (), patch: tuple[model.AuthorityEvidence, ...] = (), gates: tuple[model.GenericCfgGateResult, ...] = (), claims: tuple[model.UnflattenClaim, ...] | None = None, proposal: model.ProposedUnflattenContract | None = None) -> model.DerivedUnflattenPreparationInputs:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model)) if proposal is None else proposal
    if tuple(proposal.use_def_witness.redirect_owner_refs) != tuple(proposal.plan_inputs.dispatcher_member_refs):
        object.__setattr__(proposal.use_def_witness, "redirect_owner_refs", proposal.plan_inputs.dispatcher_member_refs)
    claims = proposal.claims if claims is None else claims
    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    def normalize_value_flow(subjects: tuple[model.SemanticSubjectRef, ...]) -> tuple[model.SemanticSubjectRef, ...]:
        return tuple(
            _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.VALUE_FLOW,
                role=model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
                block_ref=None, anchor_ea=None,
                locator=model.ValueFlowSubjectLocator(
                    proposal.use_def_witness.fragment_id,
                    proposal.use_def_witness.state_identity,
                    proposal.use_def_witness.redirect_owner_refs,
                ),
            ) if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW else subject
            for subject in subjects
        )
    source_subjects = normalize_value_flow(source_subjects)
    terminal_effect_subjects = []
    for subject in source_subjects:
        if (
            subject.role is not model.SemanticSubjectRole.TERMINAL_SITE
            or type(subject.locator) is not model.TerminalSubjectLocator
        ):
            continue
        effect_kind = {
            model.TerminalKind.RETURN: model.EffectSiteKind.RETURN,
            model.TerminalKind.TRAP: model.EffectSiteKind.TRAP,
            model.TerminalKind.NORETURN_CALL: model.EffectSiteKind.CALL,
        }.get(subject.locator.terminal_kind)
        if effect_kind is not None:
            terminal_effect_subjects.append(_subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.EFFECT,
                role=model.SemanticSubjectRole.EFFECT_SITE,
                block_ref=subject.block_ref,
                anchor_ea=subject.anchor_ea,
                locator=model.EffectSubjectLocator(
                    subject.locator.block_ref,
                    subject.locator.anchor_ea,
                    subject.locator.instruction_ea,
                    effect_kind,
                ),
            ))
    source_subjects = tuple({
        item.subject_id: item for item in (*source_subjects, *terminal_effect_subjects)
    }.values())
    if source_subjects and not any(item.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW for item in source_subjects):
        source_subjects = (*source_subjects, _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.VALUE_FLOW,
            role=model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
            block_ref=None, anchor_ea=None,
            locator=model.ValueFlowSubjectLocator(
                proposal.use_def_witness.fragment_id,
                proposal.use_def_witness.state_identity,
                proposal.use_def_witness.redirect_owner_refs,
            ),
        ))
    # This fixture is deliberately proposal-complete: every plan-input and
    # producer-claim subject is explicit before bindings are built.
    required_subjects = (
        _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "0"),
        _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0"),
        _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1"),
        _role_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, "2"),
        *(subject for claim in claims for subject in (
            (claim.retired_route_subject, claim.replacement_route_subject,
             claim.source_subject, *claim.destination_subjects)
            if type(claim) is model.EquivalentSemanticRouteClaim
            else (claim.infrastructure_subject, claim.corridor_subject, *claim.member_subjects)
            if type(claim) is model.RetiredDispatcherInfrastructureClaim
            else (claim.effect_subject, claim.source_subject, claim.predicate_subject,
                  claim.selected_target_subject, claim.discarded_effect_subject)
            if type(claim) is model.ExactInfeasibleEffectClaim
            else (claim.owner_subject,)
            if type(claim) is model.LocalAliasEffectScalarizationClaim
            else (claim.cycle_subject, claim.cleanup_source_subject, claim.terminal_subject)
        )),
    )
    by_id = {subject.subject_id: subject for subject in (*source_subjects, *required_subjects)}
    source_subjects = tuple(by_id.values())
    candidate_subjects = source_subjects if candidate_subjects is None else candidate_subjects
    candidate_subjects = normalize_value_flow(candidate_subjects)
    supplied_gates = {item.gate: item for item in gates}
    gate_roles = {
        model.GenericCfgGateKind.ENTRY_REACHABILITY: model.SemanticSubjectRole.SOURCE_ENTRY,
        model.GenericCfgGateKind.EFFECTFUL_REACHABILITY: model.SemanticSubjectRole.EFFECT_SITE,
        model.GenericCfgGateKind.TERMINAL_REACHABILITY: model.SemanticSubjectRole.TERMINAL_SITE,
    }
    def default_gate_subject_ids(gate: model.GenericCfgGateKind) -> tuple[str, ...]:
        scoped = tuple(
            subject for subject in source_subjects
            if subject.role is gate_roles[gate]
        )
        if gate is model.GenericCfgGateKind.EFFECTFUL_REACHABILITY:
            scoped = tuple(
                subject for subject in scoped
                if type(subject.locator) is model.EffectSubjectLocator
                and subject.locator.effect_kind in {
                    model.EffectSiteKind.CALL,
                    model.EffectSiteKind.STORE,
                }
            )
        elif gate is model.GenericCfgGateKind.TERMINAL_REACHABILITY:
            scoped = tuple(
                subject for subject in scoped
                if type(subject.locator) is model.TerminalSubjectLocator
                and subject.locator.terminal_kind in {
                    model.TerminalKind.RETURN,
                    model.TerminalKind.STOP,
                }
            )
        return tuple(subject.subject_id for subject in scoped)
    gates = tuple(
        supplied_gates.get(
            item,
            model.GenericCfgGateResult(
                item, True,
                default_gate_subject_ids(item),
                (), "not-applicable",
            ),
        )
        for item in model.GenericCfgGateKind
    )
    if candidate_bindings is None:
        candidate_binding_map = {
            item.subject.subject_id: item
            for item in (
                _binding(item, phase, 4, fingerprint=authority_id("candidate-fp"))
                for item in candidate_subjects
            )
        }
        candidate_bindings = tuple(
            candidate_binding_map.get(
                item.subject_id,
                _binding(
                    item, phase, 4, status=model.SubjectBindingStatus.MISSING,
                    fingerprint=authority_id("candidate-fp"),
                ),
            )
            for item in source_subjects
        ) + tuple(
            value for key, value in candidate_binding_map.items()
            if key not in {item.subject_id for item in source_subjects}
        )
    else:
        provided = {item.subject.subject_id for item in candidate_bindings}
        candidate_bindings = tuple(candidate_bindings) + tuple(
            _binding(
                item, phase, 4, status=model.SubjectBindingStatus.MISSING,
                fingerprint=authority_id("candidate-fp"),
            )
            for item in source_subjects if item.subject_id not in provided
        )
    source_subjects = tuple(sorted(source_subjects, key=lambda item: item.subject_id))
    candidate_subjects = tuple(sorted(candidate_subjects, key=lambda item: item.subject_id))
    source_bindings = source_bindings if source_bindings is not None else tuple(
        _binding(item, model.UnflattenAuthorityPhase.PRODUCER_FORECAST, fingerprint=authority_id("source-fp"))
        for item in source_subjects
    )
    relations = []
    def relation(subject, dimension, provenance="fixture-relation", target=None):
        relations.append(model.ConditionalSubjectRelation(
            subject.subject_id, target.subject_id if target is not None else subject.subject_id,
            dimension, authority_id(provenance),
        ))
    route_claims = tuple(claim for claim in claims if type(claim) is model.EquivalentSemanticRouteClaim)
    for subject in source_subjects:
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE and any(
            candidate == subject for candidate in candidate_subjects
        ):
            relation(subject, model.SafetyDimension.TOPOLOGY_INTEGRITY)
        if subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION:
            if any(
                candidate.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
                and candidate.block_ref == subject.block_ref and candidate.anchor_ea == subject.anchor_ea
                for candidate in source_subjects
            ):
                relation(subject, model.SafetyDimension.HANDLER_REACHABILITY)
                for candidate in source_subjects:
                    if candidate.role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER and candidate.block_ref == subject.block_ref and candidate.anchor_ea == subject.anchor_ea:
                        relation(subject, model.SafetyDimension.HANDLER_REACHABILITY, "fixture-handler-owner", candidate)
            if any(
                candidate.role is model.SemanticSubjectRole.TERMINAL_SITE
                and candidate.block_ref == subject.block_ref and candidate.anchor_ea == subject.anchor_ea
                for candidate in source_subjects
            ):
                relation(subject, model.SafetyDimension.TERMINAL_REACHABILITY)
                for candidate in source_subjects:
                    if candidate.role is model.SemanticSubjectRole.TERMINAL_SITE and candidate.block_ref == subject.block_ref and candidate.anchor_ea == subject.anchor_ea:
                        relation(subject, model.SafetyDimension.TERMINAL_REACHABILITY, "fixture-terminal-owner", candidate)
        if subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY and any(
            claim.source_subject.block_ref == subject.block_ref and claim.source_subject.anchor_ea == subject.anchor_ea
            for claim in route_claims
        ):
            relation(subject, model.SafetyDimension.ROUTE_EQUIVALENCE)
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE and any(
            claim.infrastructure_subject.block_ref == subject.block_ref and claim.infrastructure_subject.anchor_ea == subject.anchor_ea
            for claim in claims if type(claim) is model.RetiredDispatcherInfrastructureClaim
        ):
            relation(subject, model.SafetyDimension.ROUTE_EQUIVALENCE)
    for helper in candidate_subjects:
        if helper.role is model.SemanticSubjectRole.PLANNED_HELPER and any(
            helper == claim.replacement_route_subject for claim in route_claims
        ):
            relation(helper, model.SafetyDimension.ROUTE_EQUIVALENCE)
    relations = tuple(sorted(relations, key=lambda item: (item.source_subject_id, item.target_subject_id, item.dimension.value, item.provenance_id)))
    metrics = model.PreparationBuildMetrics(1, 1, 1.25)
    patch_payloads = tuple(item.payload for item in patch if type(item.payload) is model.PatchStepEvidencePayload)
    source_subject_ids = tuple(source_subjects)
    candidate_subject_ids = tuple(candidate_subjects)
    receipt = _receipt_fixture(
        proposal_id=_digest(proposal), plan_id=proposal.plan_id,
        source_fingerprint=authority_id("source-fp"), candidate_fingerprint=authority_id("candidate-fp"),
        source_generation=3, candidate_generation=4,
        source_inventory_digest=_digest(source_subject_ids),
        candidate_inventory_digest=_digest(candidate_subject_ids),
        source_binding_digest=_digest(tuple(sorted(source_bindings, key=lambda item: item.subject.subject_id))),
        candidate_binding_digest=_digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))),
        route_expansion_digest=_digest(tuple(item for item in source_subjects if item.role in {model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION})),
        effect_catalog_digest=_digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.EFFECT_SITE)),
        terminal_catalog_digest=_digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.TERMINAL_SITE)),
        plan_input_digest=_digest(tuple(item.subject_id for item in source_subjects if item.role in {model.SemanticSubjectRole.SOURCE_ENTRY, model.SemanticSubjectRole.DISPATCHER_ENTRY, model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, model.SemanticSubjectRole.AUTHORITATIVE_HANDLER})),
        dispatcher_member_digest=_digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE)),
        planned_helper_digest=_digest(tuple(item.subject_id for item in candidate_subjects if item.role is model.SemanticSubjectRole.PLANNED_HELPER)),
        patch_step_digest=_digest(tuple(sorted(patch_payloads, key=lambda item: (item.plan_id, item.step_index))),),
        conditional_relation_digest=_digest(relations), metrics=metrics,
    )
    def fixture_inventory(
        phase_value: model.UnflattenAuthorityPhase,
        fingerprint: str,
        generation: int,
        bindings: tuple[model.PhaseSubjectBinding, ...],
        subjects: tuple[model.SemanticSubjectRef, ...],
        source_partition: tuple[model.SemanticSubjectRef, ...] | None = None,
        site_subjects: tuple[model.SemanticSubjectRef, ...] | None = None,
    ) -> model.SemanticGraphInventory:
        # This helper models a closed inventory: typed site subjects become
        # raw instruction rows and their bindings are widened to include
        # those exact native EAs.
        unique = {
            binding.block_ref: binding
            for binding in bindings
            if binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.block_ref is not None
        }
        effects_by_owner = {}
        terminals_by_owner = {}
        for subject in subjects if site_subjects is None else site_subjects:
            if subject.block_ref is None:
                continue
            if (
                subject.role is model.SemanticSubjectRole.EFFECT_SITE
                and type(subject.locator) is model.EffectSubjectLocator
            ):
                effects_by_owner.setdefault(subject.block_ref, []).append(subject.locator)
            if (
                subject.role is model.SemanticSubjectRole.TERMINAL_SITE
                and type(subject.locator) is model.TerminalSubjectLocator
            ):
                terminals_by_owner.setdefault(subject.block_ref, []).append(subject.locator)
        widened_bindings = []
        for binding in bindings:
            if binding.status is not model.SubjectBindingStatus.UNIQUE or binding.block_ref is None:
                widened_bindings.append(binding)
                continue
            eas = {binding.anchor_ea, *binding.native_instruction_eas}
            eas.update(locator.instruction_ea for locator in effects_by_owner.get(binding.block_ref, ()))
            eas.update(locator.instruction_ea for locator in terminals_by_owner.get(binding.block_ref, ()))
            return_eas = {
                locator.instruction_ea
                for locator in effects_by_owner.get(binding.block_ref, ())
                if locator.effect_kind is model.EffectSiteKind.RETURN
            }
            return_eas.update(
                locator.instruction_ea
                for locator in terminals_by_owner.get(binding.block_ref, ())
                if locator.terminal_kind is model.TerminalKind.RETURN
            )
            widened_bindings.append(replace(
                binding,
                native_instruction_eas=tuple(sorted(eas, key=lambda ea: (ea not in return_eas, ea))),
            ))
        bindings = tuple(widened_bindings)
        unique = {
            binding.block_ref: binding
            for binding in bindings
            if binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.block_ref is not None
        }
        serials = tuple(binding.serial for binding in sorted(unique.values(), key=lambda item: item.serial))
        blocks = tuple(
            model.InventoryBlockObservation(
                binding.serial,
                binding.block_ref,
                binding.anchor_ea,
                binding.native_instruction_eas,
                (serials[index - 1],) if index else (),
                (serials[index + 1],) if index + 1 < len(serials) else (),
                next(
                    (
                        ea for ea in reversed(binding.native_instruction_eas)
                        if any(
                            locator.instruction_ea == ea
                            and locator.effect_kind is model.EffectSiteKind.RETURN
                            for locator in effects_by_owner.get(binding.block_ref, ())
                        ) or any(
                            locator.instruction_ea == ea
                            and locator.terminal_kind is model.TerminalKind.RETURN
                            for locator in terminals_by_owner.get(binding.block_ref, ())
                        )
                    ),
                    None,
                ),
                tuple(
                    model.InventoryInstructionObservation(
                        ordinal,
                        ea,
                        0,
                        0,
                        next(
                            (
                                model.InsnKind.STORE
                                if locator.effect_kind is model.EffectSiteKind.STORE
                                else model.InsnKind.CALL
                                if locator.effect_kind is model.EffectSiteKind.CALL
                                else model.InsnKind.TRAP
                                if locator.effect_kind is model.EffectSiteKind.TRAP
                                else model.InsnKind.RET
                                for locator in effects_by_owner.get(binding.block_ref, ())
                                if locator.instruction_ea == ea
                            ),
                            next(
                                (
                                    model.InsnKind.RET
                                    if locator.terminal_kind is model.TerminalKind.RETURN
                                    else model.InsnKind.TRAP
                                    if locator.terminal_kind is model.TerminalKind.TRAP
                                    else model.InsnKind.CALL
                                    if locator.terminal_kind is model.TerminalKind.NORETURN_CALL
                                    else model.InsnKind.NOP
                                    for locator in terminals_by_owner.get(binding.block_ref, ())
                                    if locator.instruction_ea == ea
                                ),
                                model.InsnKind.NOP,
                            ),
                        ),
                        model.ControlTransferKind.RETURN
                        if any(
                            locator.instruction_ea == ea
                            and locator.effect_kind is model.EffectSiteKind.RETURN
                            for locator in effects_by_owner.get(binding.block_ref, ())
                        ) or any(
                            locator.instruction_ea == ea
                            and locator.terminal_kind is model.TerminalKind.RETURN
                            for locator in terminals_by_owner.get(binding.block_ref, ())
                        ) else None,
                        any(
                            locator.instruction_ea == ea
                            and locator.effect_kind is model.EffectSiteKind.CALL
                            for locator in effects_by_owner.get(binding.block_ref, ())
                        ),
                        None,
                    )
                    for ordinal, ea in enumerate(binding.native_instruction_eas)
                ),
                model.BlockKind.STOP
                if any(
                    locator.terminal_kind is model.TerminalKind.STOP
                    for locator in terminals_by_owner.get(binding.block_ref, ())
                ) else model.BlockKind.UNKNOWN,
                binding.anchor_ea,
            )
            for index, binding in enumerate(sorted(unique.values(), key=lambda item: item.serial))
        )
        effects = tuple(
            item
            for block in blocks
            for item in model.resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea if block.anchor_ea is not None else 0,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )[0]
        )
        terminals = tuple(
            item
            for block in blocks
            for item in model.resolve_inventory_block_sites(
                serial=block.serial,
                owner_ref=block.block_ref,
                owner_anchor_ea=block.anchor_ea if block.anchor_ea is not None else 0,
                block_kind=block.block_kind,
                successor_serials=block.successor_serials,
                instruction_observations=block.instruction_observations,
            )[1]
        )
        topology = tuple(
            incidence
            for block in blocks
            if block.successor_serials
            for incidence in (
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.SUCCESSOR,
                    block.serial,
                    block.successor_serials[0],
                    block.transfer_ea,
                ),
                model.InventoryTopologyIncidence(
                    model.TopologyIncidenceKind.PREDECESSOR,
                    block.successor_serials[0],
                    block.serial,
                    block.transfer_ea,
                ),
            )
        )
        effects = tuple(sorted(effects, key=lambda item: (item.owner_serial, item.instruction_ordinal, item.instruction_ea, item.effect_kind.value)))
        terminals = tuple(sorted(terminals, key=lambda item: (item.owner_serial, item.instruction_ordinal is None, item.instruction_ordinal if item.instruction_ordinal is not None else -1, item.instruction_ea, item.terminal_kind.value)))
        topology = tuple(sorted(topology, key=lambda item: (item.kind.value, item.owner_serial, item.peer_serial, -1)))
        closure = serials
        partition = subjects if source_partition is None else source_partition
        digest = semantic_graph_inventory_digest(
            phase_value, fingerprint, generation, blocks, subjects, bindings,
            effects, terminals, topology, closure,
            blocks[0].serial if blocks else 0,
            tuple(item.subject_id for item in partition),
        )
        return model.SemanticGraphInventory(
            phase_value, fingerprint, generation, blocks, subjects, bindings,
            effects, terminals, topology, digest, closure,
            blocks[0].serial if blocks else 0,
            tuple(item.subject_id for item in partition),
        )

    source_inventory = fixture_inventory(
        model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        authority_id("source-fp"), 3,
        tuple(sorted(source_bindings, key=lambda item: item.subject.subject_id)),
        source_subjects,
    )
    source_bindings = source_inventory.bindings
    candidate_inventory = fixture_inventory(
        phase, authority_id("candidate-fp"), 4,
        tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id)),
        tuple(sorted({item.subject_id: item for item in (*source_subjects, *candidate_subjects)}.values(), key=lambda item: item.subject_id)),
        source_subjects,
        candidate_subjects,
    )
    candidate_bindings = candidate_inventory.bindings
    object.__setattr__(
        receipt,
        "source_binding_digest",
        _digest(tuple(sorted(source_bindings, key=lambda item: item.subject.subject_id))),
    )
    object.__setattr__(
        receipt,
        "candidate_binding_digest",
        _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))),
    )
    object.__setattr__(
        receipt,
        "effect_catalog_digest",
        _digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.EFFECT_SITE)),
    )
    object.__setattr__(
        receipt,
        "terminal_catalog_digest",
        _digest(tuple(item.subject_id for item in source_subjects if item.role is model.SemanticSubjectRole.TERMINAL_SITE)),
    )
    object.__setattr__(receipt, "source_inventory_digest", source_inventory.inventory_digest)
    object.__setattr__(receipt, "candidate_inventory_digest", candidate_inventory.inventory_digest)
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
    return model.DerivedUnflattenPreparationInputs(
        proposal=proposal, claims=claims, source_subjects=source_subjects,
        preparation_receipt=receipt,
        candidate_subjects=candidate_subjects,
        source_bindings=source_bindings,
        candidate_bindings=candidate_bindings,
        conditional_relations=relations, lineage_evidence=lineage, patch_step_evidence=patch,
        generic_gates=gates,
        source_fingerprint=authority_id("source-fp"), candidate_fingerprint=authority_id("candidate-fp"),
        source_generation=3, candidate_generation=4,
        preparation_metrics=metrics,
        source_inventory=source_inventory,
        candidate_inventory=candidate_inventory,
        phase_build_metrics=model.PhaseBuildMetrics(phase, 1, 1, 1.25),
    )


def test_case_builder_accepts_only_closed_derived_inputs() -> None:
    signature = inspect.signature(build_semantic_case)
    assert tuple(signature.parameters) == ("authority_id", "phase", "inputs")
    with pytest.raises(TypeError):
        build_semantic_case(
            authority_id="sha256:" + "a" * 64,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            inputs=None,
            plan=object(),
        )
    with pytest.raises(TypeError):
        build_semantic_case(
            authority_id="sha256:" + "a" * 64,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            inputs=None,
            projection=object(),
        )
    with pytest.raises(TypeError):
        build_semantic_case(
            authority_id="sha256:" + "a" * 64,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            inputs=None,
            graph=object(),
        )
    with pytest.raises(TypeError):
        build_semantic_case(
            authority_id="sha256:" + "a" * 64,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            inputs=None,
            callback=lambda: None,
        )


def test_prepared_authority_accepts_canonical_bound_route_endpoints() -> None:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    inputs = _complete_inputs(
        source_subjects=(_role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0"),),
        proposal=proposal,
    )
    authority = authority_id("prepared-route-authority")
    case = build_semantic_case(
        authority_id=authority,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    proof = proposal.route_evidence.route_proofs[0]
    source = BoundSemanticBlock(1, proof.source_identity, proof.source_anchor_ea)
    destinations = tuple(
        BoundSemanticRouteDestination(
            destination,
            BoundSemanticBlock(
                index + 2,
                destination.target_identity,
                destination.target_anchor_ea,
            ),
        )
        for index, destination in enumerate(proof.destinations)
    )
    bound_routes = BoundCanonicalSemanticEvidence(
        proposal.route_evidence,
        (BoundSemanticRoute(proof, source, destinations),),
    )

    plan = PatchPlan(
        plan_id=proposal.plan_id,
        snapshot_id=authority_id("prepared-snapshot"),
        source_generation=inputs.source_generation,
        source_coordinates=tuple(
            (block.block_ref, serial)
            for serial, block in enumerate(proposal.source_identity_catalog.blocks)
        ),
        unflatten_proposal=proposal,
    )

    expected_coordinates = tuple(
        sorted(plan.source_coordinates, key=lambda item: (repr(item[0]), item[1]))
    )
    prepared = model.PreparedUnflattenAuthority(
        authority_id=authority,
        route=model.UnflattenPlanRoute.ORDINARY,
        owning_plan=plan,
        proposal=proposal,
        claims=case.claims,
        bound_routes=bound_routes,
        snapshot_id=plan.snapshot_id,
        source_maturity=None,
        source_coordinate_digest=canonical_authority_id(expected_coordinates),
        source_fingerprint=inputs.source_fingerprint,
        projected_fingerprint=inputs.candidate_fingerprint,
        source_generation=inputs.source_generation,
        projected_generation=inputs.candidate_generation,
        source_bindings=inputs.source_bindings,
        projected_bindings=case.bindings,
        projected_case=case,
        source_inventory=inputs.source_inventory,
        source_inputs=inputs,
    )
    assert prepared.bound_routes.routes[0].destinations[0].evidence.role is proof.destinations[0].role
    with pytest.raises(ValueError, match="source bindings"):
        replace(prepared, source_bindings=prepared.source_bindings[:-1])
    swapped_destination = BoundSemanticRouteDestination(
        proof.destinations[0],
        BoundSemanticBlock(99, proof.source_identity, proof.source_anchor_ea),
    )
    swapped_routes = BoundCanonicalSemanticEvidence(
        proposal.route_evidence,
        (BoundSemanticRoute(proof, source, (swapped_destination,)),),
    )
    with pytest.raises(ValueError, match="destinations"):
        replace(prepared, bound_routes=swapped_routes)
    attempt = model.TransactionAttemptId(
        plan_id=proposal.plan_id, session_id="prepared-session",
        generation=inputs.candidate_generation, attempt_id="prepared-attempt",
    )
    live_maturity = MaturityEnvelope(ir=None, provider="test", provider_id=0)
    patch_binding = BoundPatchPlan(
        plan=plan,
        attempt_id=attempt,
        session_id=attempt.session_id,
        generation=attempt.generation,
        maturity=live_maturity,
        bindings=(),
    )
    with pytest.raises(TypeError, match="live_maturity"):
        model.BoundUnflattenAuthority(
            binding_id=authority_id("prepared-binding"), prepared=prepared,
            attempt_id=attempt, session_id=attempt.session_id,
            generation=attempt.generation, live_maturity=4, live_bindings=(),
            patch_binding=patch_binding,
        )
    bound = model.BoundUnflattenAuthority(
        binding_id=bound_unflatten_binding_id(prepared, patch_binding), prepared=prepared,
        attempt_id=attempt, session_id=attempt.session_id,
        generation=attempt.generation,
        live_maturity=live_maturity, live_bindings=(), patch_binding=patch_binding,
    )
    assert isinstance(bound.live_maturity, MaturityEnvelope)
    with pytest.raises(ValueError, match="binding_id"):
        replace(bound, binding_id=authority_id("unrelated-valid-digest"))


def test_fragment_wide_value_flow_identity_and_use_def_are_total() -> None:
    """The use-def witness owns one fragment-wide, fully classified cell pair."""

    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "value-flow-total")
    case = build_semantic_case(
        authority_id=authority_id("value-flow-total"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )

    value_flow = next(
        subject for subject in case.subjects
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    cells = {
        cell.key.dimension: cell
        for cell in case.obligation_index.cells
        if cell.key.subject == value_flow
    }
    assert set(cells) == {
        model.SafetyDimension.IDENTITY_BINDING,
        model.SafetyDimension.USE_DEF_INTEGRITY,
    }
    assert cells[model.SafetyDimension.IDENTITY_BINDING].state is model.ObligationState.SATISFIED
    assert cells[model.SafetyDimension.USE_DEF_INTEGRITY].state is model.ObligationState.SATISFIED


def test_use_def_audit_evidence_is_evaluator_owned() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "audit-injection")
    inputs = _complete_inputs(source_subjects=(source_entry,))
    value_flow = next(
        subject for subject in inputs.source_subjects
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    payload = model.UseDefAuditEvidencePayload(
        value_flow.locator.fragment_id, value_flow.locator.state_identity,
        True, True, 0, (),
    )
    injected = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.USE_DEF_AUDIT,
        value_flow, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    with pytest.raises(ValueError, match="evaluator-owned"):
        build_semantic_case(
            authority_id=authority_id("audit-injection"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(inputs, lineage_evidence=(injected,)),
        )


def test_value_flow_identity_is_conjunctive_over_every_owner_binding() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "owner-conjunction")
    inputs = _complete_inputs(source_subjects=(source_entry,))
    good = build_semantic_case(
        authority_id=authority_id("owner-conjunction-good"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=inputs,
    )
    value_flow = next(
        subject for subject in good.subjects
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    good_cell = next(
        cell for cell in good.obligation_index.cells
        if cell.key.subject == value_flow
        and cell.key.dimension is model.SafetyDimension.IDENTITY_BINDING
    )
    assert good_cell.supporting_justification_ids
    owner_binding = next(
        binding for binding in inputs.candidate_bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        and binding.subject.block_ref in value_flow.locator.redirect_owner_refs
    )
    mutations = (
        replace(
            owner_binding, status=model.SubjectBindingStatus.MISSING,
            block_ref=None, serial=None, anchor_ea=None, native_instruction_eas=(),
        ),
        replace(owner_binding, generation=999),
    )
    for index, mutated in enumerate(mutations):
        candidate_bindings = tuple(
            mutated if binding is owner_binding else binding
            for binding in inputs.candidate_bindings
        )
        receipt = inputs.preparation_receipt
        object.__setattr__(
            receipt, "candidate_binding_digest",
            _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))),
        )
        object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
        object.__setattr__(
            inputs.candidate_inventory, "bindings",
            tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id)),
        )
        object.__setattr__(
            inputs.candidate_inventory, "inventory_digest",
            semantic_graph_inventory_digest(
                inputs.candidate_inventory.phase,
                inputs.candidate_inventory.graph_fingerprint,
                inputs.candidate_inventory.generation,
                inputs.candidate_inventory.blocks,
                inputs.candidate_inventory.subjects,
                inputs.candidate_inventory.bindings,
                inputs.candidate_inventory.effects,
                inputs.candidate_inventory.terminals,
                inputs.candidate_inventory.topology,
                inputs.candidate_inventory.reachable_serials,
                inputs.candidate_inventory.entry_serial,
                inputs.candidate_inventory.source_subject_ids,
            ),
        )
        object.__setattr__(
            receipt, "candidate_inventory_digest",
            inputs.candidate_inventory.inventory_digest,
        )
        object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
        if index == 0:
            case = build_semantic_case(
                authority_id=authority_id("owner-conjunction-missing"),
                phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                inputs=replace(inputs, candidate_bindings=candidate_bindings),
            )
            cell = next(
                cell for cell in case.obligation_index.cells
                if cell.key.subject == value_flow
                and cell.key.dimension is model.SafetyDimension.IDENTITY_BINDING
            )
            assert not cell.supporting_justification_ids
            assert cell.refuting_justification_ids
        else:
            with pytest.raises(ValueError, match="binding|inventory"):
                replace(inputs, candidate_bindings=candidate_bindings)

    object.__setattr__(
        inputs.candidate_inventory, "bindings", inputs.candidate_bindings,
    )
    object.__setattr__(
        inputs.candidate_inventory, "inventory_digest",
        semantic_graph_inventory_digest(
            inputs.candidate_inventory.phase,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.candidate_inventory.generation,
            inputs.candidate_inventory.blocks,
            inputs.candidate_inventory.subjects,
            inputs.candidate_inventory.bindings,
            inputs.candidate_inventory.effects,
            inputs.candidate_inventory.terminals,
            inputs.candidate_inventory.topology,
            inputs.candidate_inventory.reachable_serials,
            inputs.candidate_inventory.entry_serial,
            inputs.candidate_inventory.source_subject_ids,
        ),
    )
    object.__setattr__(receipt, "candidate_binding_digest", _digest(inputs.candidate_bindings))
    object.__setattr__(receipt, "candidate_inventory_digest", inputs.candidate_inventory.inventory_digest)
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))

    unrelated = next(
        binding for binding in inputs.candidate_bindings
        if binding.subject.role is model.SemanticSubjectRole.SOURCE_ENTRY
        and binding.subject.block_ref in value_flow.locator.redirect_owner_refs
    )
    unrelated_bad = replace(
        unrelated, status=model.SubjectBindingStatus.MISSING,
        block_ref=None, serial=None, anchor_ea=None, native_instruction_eas=(),
    )
    candidate_bindings = tuple(
        unrelated_bad if binding is unrelated else binding
        for binding in inputs.candidate_bindings
    )
    receipt = inputs.preparation_receipt
    object.__setattr__(
        receipt, "candidate_binding_digest",
        _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))),
    )
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
    object.__setattr__(
        inputs.candidate_inventory, "bindings",
        tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id)),
    )
    object.__setattr__(
        inputs.candidate_inventory, "inventory_digest",
        semantic_graph_inventory_digest(
            inputs.candidate_inventory.phase,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.candidate_inventory.generation,
            inputs.candidate_inventory.blocks,
            inputs.candidate_inventory.subjects,
            inputs.candidate_inventory.bindings,
            inputs.candidate_inventory.effects,
            inputs.candidate_inventory.terminals,
            inputs.candidate_inventory.topology,
            inputs.candidate_inventory.reachable_serials,
            inputs.candidate_inventory.entry_serial,
            inputs.candidate_inventory.source_subject_ids,
        ),
    )
    object.__setattr__(receipt, "candidate_inventory_digest", inputs.candidate_inventory.inventory_digest)
    object.__setattr__(receipt, "receipt_id", receipt_id(receipt))
    case = build_semantic_case(
        authority_id=authority_id("owner-conjunction-unrelated"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=replace(inputs, candidate_bindings=candidate_bindings),
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key.subject == value_flow
        and cell.key.dimension is model.SafetyDimension.IDENTITY_BINDING
    )
    assert cell.supporting_justification_ids


def test_contextual_justification_validation_rejects_forged_stale_support() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "contextual-forge")
    case = build_semantic_case(
        authority_id=authority_id("contextual-forge"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="binding|context"):
        _validate_justification_graph(
            case.justifications, case.required_obligations, case.evidence, case.phase,
            case.claims, case.conditional_relations,
            candidate_fingerprint=authority_id("forged-candidate-fingerprint"),
            candidate_generation=case.candidate_generation,
            bindings=case.bindings, subjects=case.subjects,
        )


def test_contextual_justification_validation_rejects_forged_clean_audit() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "clean-audit-forge")
    case = build_semantic_case(
        authority_id=authority_id("clean-audit-forge"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    audit_justification = next(
        item for item in case.justifications
        if item.rule is model.UnflattenJustificationRule.USE_DEF_AUDIT_CLEAN
    )
    audit_evidence = next(
        item for item in case.evidence
        if item.kind is model.AuthorityEvidenceKind.USE_DEF_AUDIT
    )
    forged_payload = replace(audit_evidence.payload, executed=False)
    forged_evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.USE_DEF_AUDIT,
        audit_evidence.subject, case.phase, forged_payload,
    )
    forged_justification = _justification_factory(
        model.AuthorityJustification,
        rule=audit_justification.rule,
        premise_ids=(forged_evidence.evidence_id,),
        conclusion=audit_justification.conclusion,
        polarity=audit_justification.polarity,
        phase=audit_justification.phase,
        claim_id=None,
    )
    evidence = tuple(
        forged_evidence if item.evidence_id == audit_evidence.evidence_id else item
        for item in case.evidence
    )
    justifications = tuple(
        forged_justification if item.justification_id == audit_justification.justification_id else item
        for item in case.justifications
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="clean use-def|contradictory"):
        _validate_justification_graph(
            justifications, case.required_obligations, evidence, case.phase,
            case.claims, case.conditional_relations,
            candidate_fingerprint=case.candidate_fingerprint,
            candidate_generation=case.candidate_generation,
            bindings=case.bindings, subjects=case.subjects,
        )


def test_value_flow_unique_binding_requires_exact_owner_premise_set() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "owner-premise-set")
    case = build_semantic_case(
        authority_id=authority_id("owner-premise-set"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    justification = next(
        item for item in case.justifications
        if item.conclusion.subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
        and item.rule is model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING
    )
    assert len(justification.premise_ids) == 2
    for premise_ids in (
        justification.premise_ids[:-1],
        (*justification.premise_ids, justification.premise_ids[0]),
    ):
        values = {
            name: getattr(justification, name)
            for name in justification.__dataclass_fields__
            if name != "justification_id"
        }
        values["premise_ids"] = premise_ids
        if len(set(premise_ids)) != len(premise_ids):
            with pytest.raises(ValueError, match="duplicate"):
                _justification_factory(model.AuthorityJustification, **values)
            continue
        forged = _justification_factory(model.AuthorityJustification, **values)
        from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
        with pytest.raises(ValueError, match="owner|premise|duplicate"):
            _validate_justification_graph(
                tuple(forged if item is justification else item for item in case.justifications),
                case.required_obligations, case.evidence, case.phase,
                case.claims, case.conditional_relations,
                candidate_fingerprint=case.candidate_fingerprint,
                candidate_generation=case.candidate_generation,
                bindings=case.bindings, subjects=case.subjects,
            )
    wire = json.loads(canonical_bytes(case).decode("ascii"))
    def omit_owner_premise(value: object) -> bool:
        if isinstance(value, dict) and value.get("t") == "record" and value.get("n") == "AuthorityJustification":
            for name, encoded in value["v"]:
                if name == "premise_ids" and len(encoded.get("v", ())) == 2:
                    encoded["v"] = encoded["v"][:-1]
                    return True
        if isinstance(value, dict):
            return any(omit_owner_premise(item) for item in value.values())
        if isinstance(value, list):
            return any(omit_owner_premise(item) for item in value)
        return False
    assert omit_owner_premise(wire)
    with pytest.raises(ValueError, match="premise|record|case"):
        canonical_decode(json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii"))
    omitted_owner = next(
        subject for subject in case.subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        and subject.block_ref == justification.conclusion.subject.locator.redirect_owner_refs[-1]
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="owner|subject|premise"):
        _validate_justification_graph(
            case.justifications, case.required_obligations, case.evidence, case.phase,
            case.claims, case.conditional_relations,
            candidate_fingerprint=case.candidate_fingerprint,
            candidate_generation=case.candidate_generation,
            bindings=tuple(item for item in case.bindings if item.subject.subject_id != omitted_owner.subject_id),
            subjects=tuple(item for item in case.subjects if item.subject_id != omitted_owner.subject_id),
        )


def test_severed_use_def_rule_requires_complete_actionable_audit() -> None:
    source_entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "severed-audit-forge")
    case = build_semantic_case(
        authority_id=authority_id("severed-audit-forge"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source_entry,)),
    )
    value_flow = next(
        item for item in case.subjects
        if item.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
    )
    with pytest.raises(ValueError, match="count"):
        model.UseDefAuditEvidencePayload(
            value_flow.locator.fragment_id, value_flow.locator.state_identity,
            True, True, 2, (authority_id("only-one"),),
        )
    payloads = (
        model.UseDefAuditEvidencePayload(
            value_flow.locator.fragment_id, value_flow.locator.state_identity,
            False, True, 1, (authority_id("unavailable"),),
        ),
        model.UseDefAuditEvidencePayload(
            value_flow.locator.fragment_id, value_flow.locator.state_identity,
            True, False, 1, (authority_id("partial"),),
        ),
    )
    severed = next(
        item for item in case.justifications
        if item.rule is model.UnflattenJustificationRule.USE_DEF_AUDIT_CLEAN
    )
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    for payload in payloads:
        evidence_item = _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.USE_DEF_AUDIT,
            value_flow, case.phase, payload,
        )
        forged = _justification_factory(
            model.AuthorityJustification,
            rule=model.UnflattenJustificationRule.NON_STATE_USE_DEF_SEVERED,
            premise_ids=(evidence_item.evidence_id,),
            conclusion=severed.conclusion,
            polarity=model.EvidencePolarity.REFUTES,
            phase=case.phase,
            claim_id=None,
        )
        evidence = tuple(
            evidence_item if item.kind is model.AuthorityEvidenceKind.USE_DEF_AUDIT else item
            for item in case.evidence
        )
        justifications = tuple(
            forged if item.justification_id == severed.justification_id else item
            for item in case.justifications
        )
        with pytest.raises(ValueError, match="severance|actionable|unavailable|audit"):
            _validate_justification_graph(
                justifications, case.required_obligations, evidence, case.phase,
                case.claims, case.conditional_relations,
                candidate_fingerprint=case.candidate_fingerprint,
                candidate_generation=case.candidate_generation,
                bindings=case.bindings, subjects=case.subjects,
            )


def test_preparation_receipt_cannot_be_minted_by_callers() -> None:
    import d810.transforms.unflatten_authority.ids as authority_ids
    assert not hasattr(authority_ids, "_receipt_factory")
    with pytest.raises(TypeError, match="transaction-owned"):
        model.PreparationAuthorityReceipt(
            receipt_id=authority_id("receipt"), proposal_id=authority_id("proposal"),
            plan_id=authority_id("plan"), source_fingerprint=authority_id("source"),
            candidate_fingerprint=authority_id("candidate"), source_generation=3,
            candidate_generation=4, source_inventory_digest=authority_id("si"),
            candidate_inventory_digest=authority_id("ci"), source_binding_digest=authority_id("sb"),
            candidate_binding_digest=authority_id("cb"), route_expansion_digest=authority_id("route"),
            effect_catalog_digest=authority_id("effect"), terminal_catalog_digest=authority_id("terminal"),
            plan_input_digest=authority_id("plan-input"), dispatcher_member_digest=authority_id("members"),
            planned_helper_digest=authority_id("helpers"), patch_step_digest=authority_id("patch"),
            conditional_relation_digest=authority_id("relations"),
            metrics=model.PreparationBuildMetrics(1, 1, 1.25),
        )


def test_topology_edge_relations_require_exact_reciprocal_rows() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "edge-entry")
    peer = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "edge-peer")
    role = edge_role()
    forward = model.TopologyEdgeRelation(role, entry.subject_id, peer.subject_id, 0x1000)
    def evidence(subject, predecessors, successors, relations, candidate=None):
        candidate = relations if candidate is None else candidate
        payload = model.TopologyEvidencePayload(
            subject.subject_id, predecessors, successors, True,
            canonical_authority_id(relations), canonical_authority_id(candidate),
            expected_edge_relations=relations,
            candidate_edge_relations=candidate,
        )
        return _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
            subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
        )
    with pytest.raises(ValueError, match="reciprocal"):
        build_semantic_case(
            authority_id=authority_id("edge-missing-peer"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(entry, peer),
                lineage=(evidence(entry, (), (peer.subject_id,), (forward,)),),
            ),
        )
    # A relation without its exact peer row cannot authorize topology.


def test_topology_peer_lists_cannot_authorize_without_edge_relations() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "empty-peer-entry")
    peer = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "empty-peer-peer")

    def evidence(subject, predecessors, successors):
        payload = model.TopologyEvidencePayload(
            subject.subject_id, predecessors, successors, True,
            canonical_authority_id(()), canonical_authority_id(()),
        )
        return _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
            subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
        )

    with pytest.raises(ValueError, match="edge relations"):
        build_semantic_case(
            authority_id=authority_id("empty-peer-lists"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(entry, peer),
                lineage=(
                    evidence(entry, (), (peer.subject_id,)),
                    evidence(peer, (entry.subject_id,), ()),
                ),
            ),
        )


def test_topology_candidate_anchor_mismatch_is_refuted() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "edge-anchor-entry")
    peer = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "edge-anchor-peer")
    role = edge_role()
    expected = model.TopologyEdgeRelation(role, entry.subject_id, peer.subject_id, 0x1000)
    candidate = model.TopologyEdgeRelation(role, entry.subject_id, peer.subject_id, 0xDEAD)
    payload = model.TopologyEvidencePayload(
        entry.subject_id, (), (peer.subject_id,), True,
        canonical_authority_id((expected,)), canonical_authority_id((candidate,)),
        expected_edge_relations=(expected,), candidate_edge_relations=(candidate,),
    )
    item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
        entry, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    case = build_semantic_case(
        authority_id=authority_id("edge-anchor-mismatch"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, peer),
            lineage=(item,),
        ),
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key.subject.subject_id == entry.subject_id
        and cell.key.dimension is model.SafetyDimension.TOPOLOGY_INTEGRITY
    )
    assert cell.state is model.ObligationState.VIOLATED


def test_topology_edge_removal_is_valid_drift_evidence() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "edge-removal-entry")
    peer = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "edge-removal-peer")
    role = edge_role()
    forward = model.TopologyEdgeRelation(role, entry.subject_id, peer.subject_id, 0x1000)
    reverse = model.TopologyEdgeRelation(role, peer.subject_id, entry.subject_id, 0x1000)

    def evidence(subject, predecessors, successors, expected):
        payload = model.TopologyEvidencePayload(
            subject.subject_id, predecessors, successors, True,
            canonical_authority_id(expected), canonical_authority_id(()),
            expected_edge_relations=expected, candidate_edge_relations=(),
        )
        return _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
            subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
        )

    case = build_semantic_case(
        authority_id=authority_id("edge-removal-drift"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, peer),
            lineage=(
                evidence(entry, (), (peer.subject_id,), (forward,)),
                evidence(peer, (), (entry.subject_id,), (reverse,)),
            ),
        ),
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(entry, model.SafetyDimension.TOPOLOGY_INTEGRITY)
    )
    assert cell.state is model.ObligationState.VIOLATED
    assert any(
        item.rule is model.UnflattenJustificationRule.TOPOLOGY_DRIFTED
        for item in case.justifications
        if item.conclusion == cell.key
    )


def test_topology_edge_addition_is_valid_drift_evidence() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "edge-addition-entry")
    peer = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "edge-addition-peer")
    role = edge_role()
    forward = model.TopologyEdgeRelation(role, entry.subject_id, peer.subject_id, 0x1000)
    reverse = model.TopologyEdgeRelation(role, peer.subject_id, entry.subject_id, 0x1000)

    def evidence(subject, candidate):
        payload = model.TopologyEvidencePayload(
            subject.subject_id, (), (), True,
            canonical_authority_id(()), canonical_authority_id(candidate),
            expected_edge_relations=(), candidate_edge_relations=candidate,
        )
        return _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
            subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
        )

    case = build_semantic_case(
        authority_id=authority_id("edge-addition-drift"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, peer),
            lineage=(evidence(entry, (forward,)), evidence(peer, (reverse,))),
        ),
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(entry, model.SafetyDimension.TOPOLOGY_INTEGRITY)
    )
    assert cell.state is model.ObligationState.VIOLATED
    assert any(
        item.rule is model.UnflattenJustificationRule.TOPOLOGY_DRIFTED
        for item in case.justifications
        if item.conclusion == cell.key
    )


def test_topology_candidate_reverse_must_be_owned_by_peer_row() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "candidate-owner-entry")
    peer = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "candidate-owner-peer")
    role = edge_role()
    forward = model.TopologyEdgeRelation(role, entry.subject_id, peer.subject_id, 0x1000)
    reverse = model.TopologyEdgeRelation(role, peer.subject_id, entry.subject_id, 0x1000)

    def evidence(subject, expected, candidate):
        predecessors = tuple(
            relation.source_subject_id for relation in expected
            if relation.target_subject_id == subject.subject_id
        )
        successors = tuple(
            relation.target_subject_id for relation in expected
            if relation.source_subject_id == subject.subject_id
        )
        payload = model.TopologyEvidencePayload(
            subject.subject_id, predecessors, successors,
            True,
            canonical_authority_id(expected), canonical_authority_id(candidate),
            expected_edge_relations=expected, candidate_edge_relations=candidate,
        )
        return _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
            subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
        )

    case = build_semantic_case(
        authority_id=authority_id("candidate-owner-drift"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, peer),
            lineage=(
                evidence(entry, (forward,), (forward, reverse)),
                evidence(peer, (reverse,), (reverse,)),
            ),
        ),
    )
    for subject in (entry, peer):
        cell = next(
            cell for cell in case.obligation_index.cells
            if cell.key == model.ObligationKey(subject, model.SafetyDimension.TOPOLOGY_INTEGRITY)
        )
        assert cell.state is model.ObligationState.VIOLATED
        assert any(
            item.rule is model.UnflattenJustificationRule.TOPOLOGY_DRIFTED
            for item in case.justifications
            if item.conclusion == cell.key
        )


def test_task4_records_and_total_result_variants_exist() -> None:
    for name in (
        "ObligationKey", "AuthorityJustification", "ObligationEvidenceCell",
        "ObligationEvidenceIndex", "SemanticSafetyCase", "FailedObligation",
        "UnflattenAuthorityVerdict", "UnflattenAuthorityNotApplicable",
        "UnflattenAuthorityPreparationAccepted", "UnflattenAuthorityPreparationRejected",
        "UnflattenAuthorityBindingAccepted", "UnflattenAuthorityBindingRejected",
        "PreparationBuildMetrics", "DerivedUnflattenPreparationInputs",
    ):
        assert hasattr(model, name)
    assert callable(evaluate_case)


def test_generic_gate_rows_are_closed_and_disjoint() -> None:
    gate = model.GenericCfgGateResult(
        model.GenericCfgGateKind.ENTRY_REACHABILITY,
        True,
        ("sha256:" + "a" * 64,),
        (),
        "ok",
    )
    assert gate.passed is True
    with pytest.raises(ValueError):
        model.GenericCfgGateResult(
            model.GenericCfgGateKind.ENTRY_REACHABILITY,
            True,
            ("sha256:" + "a" * 64,),
            ("sha256:" + "a" * 64,),
            "bad",
        )
    with pytest.raises(ValueError, match="duplicate"):
        model.GenericCfgGateResult(
            model.GenericCfgGateKind.ENTRY_REACHABILITY,
            True,
            ("sha256:" + "a" * 64, "sha256:" + "a" * 64),
            (),
            "duplicate",
        )


def test_obligation_cell_has_exact_four_state_truth_table() -> None:
    assert model.ObligationState.UNPROVEN.value == "unproven"
    assert model.ObligationState.SATISFIED.value == "satisfied"
    assert model.ObligationState.VIOLATED.value == "violated"
    assert model.ObligationState.INCONSISTENT.value == "inconsistent"


def test_role_inventory_is_exact_and_has_no_unrelated_cells() -> None:
    roles = tuple(model.SemanticSubjectRole)
    subjects = tuple(
        _role_subject(
            role,
            "2" if role is model.SemanticSubjectRole.AUTHORITATIVE_HANDLER
            else "0" if role in {
                model.SemanticSubjectRole.SOURCE_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_ENTRY,
                model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            } else f"role-{index}",
        )
        for index, role in enumerate(roles)
    )
    case = build_semantic_case(
        authority_id=authority_id("authority"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=subjects),
    )
    for subject in subjects:
        if subject.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW:
            subject = next(
                item for item in case.subjects
                if item.role is model.SemanticSubjectRole.NON_STATE_VALUE_FLOW
            )
        actual = {key.dimension for key in case.required_obligations if key.subject == subject}
        expected = set(REQUIRED_DIMENSIONS[subject.role])
        if subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY:
            expected.add(model.SafetyDimension.ROUTE_EQUIVALENCE)
        if subject.role is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION:
            expected.add(model.SafetyDimension.TERMINAL_REACHABILITY)
        if subject.role is model.SemanticSubjectRole.EFFECT_SITE:
            expected.add(model.SafetyDimension.TOPOLOGY_INTEGRITY)
        assert actual == expected


def test_phase_binding_evidence_can_only_support_identity_dimension() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "exact-evidence")
    case = build_semantic_case(
        authority_id=authority_id("authority-exact-evidence"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(source_subjects=(subject,)),
    )
    identity = next(cell for cell in case.obligation_index.cells if cell.key == model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING))
    assert identity.state is model.ObligationState.SATISFIED
    for cell in case.obligation_index.cells:
        if cell.key.subject == subject and cell.key.dimension is not model.SafetyDimension.IDENTITY_BINDING:
            for justification_id in cell.supporting_justification_ids:
                justification = next(item for item in case.justifications if item.justification_id == justification_id)
                assert all(
                    not any(
                        evidence.evidence_id == premise
                        and evidence.kind is model.AuthorityEvidenceKind.PHASE_BINDING
                        for evidence in case.evidence
                    )
                    for premise in justification.premise_ids
                )


def test_generic_entry_gate_cannot_support_structure_or_topology() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "generic-scope")
    gate = model.GenericCfgGateResult(
        model.GenericCfgGateKind.ENTRY_REACHABILITY, True, (subject.subject_id,), (), "entry-ok",
    )
    case = build_semantic_case(
        authority_id=authority_id("authority-generic-scope"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), gates=(gate,)),
    )
    for dimension in (model.SafetyDimension.STRUCTURAL_ACCOUNTING, model.SafetyDimension.TOPOLOGY_INTEGRITY):
        cell = next(item for item in case.obligation_index.cells if item.key == model.ObligationKey(subject, dimension))
        for justification_id in cell.supporting_justification_ids:
            justification = next(item for item in case.justifications if item.justification_id == justification_id)
            assert all(
                not any(
                    evidence.evidence_id == premise
                    and evidence.kind is model.AuthorityEvidenceKind.GENERIC_CFG_GATE
                    for evidence in case.evidence
                )
                for premise in justification.premise_ids
            )


def test_missing_source_subject_retains_identity_and_structure_keys() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "missing")
    case = build_semantic_case(
        authority_id=authority_id("authority-missing"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=(), candidate_bindings=()),
    )
    keys = {key.dimension for key in case.required_obligations}
    assert {model.SafetyDimension.IDENTITY_BINDING, model.SafetyDimension.STRUCTURAL_ACCOUNTING} <= keys
    assert evaluate_case(case).reason is model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED


def test_source_candidate_one_to_many_and_many_to_one_keep_source_keys() -> None:
    source = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "source")
    candidates = tuple(_role_subject(model.SemanticSubjectRole.PLANNED_HELPER, f"candidate-{i}") for i in range(2))
    case = build_semantic_case(
        authority_id=authority_id("authority-lineage"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(source,), candidate_subjects=candidates),
    )
    assert any(key.subject == source for key in case.required_obligations)
    assert all(any(key.subject == candidate for key in case.required_obligations) for candidate in candidates)


def test_justification_cells_are_four_state_and_sorted() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "cell")
    key = model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING)
    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    def cell(supporting: tuple[str, ...], refuting: tuple[str, ...]) -> model.ObligationEvidenceCell:
        return model.ObligationEvidenceCell(key, phase, supporting, refuting)
    assert cell((), ()).state is model.ObligationState.UNPROVEN
    assert cell((authority_id("support"),), ()).state is model.ObligationState.SATISFIED
    assert cell((), (authority_id("refute"),)).state is model.ObligationState.VIOLATED
    assert cell((authority_id("support"),), (authority_id("refute"),)).state is model.ObligationState.INCONSISTENT


def test_case_ids_and_private_index_reject_tampering() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "tamper")
    case = build_semantic_case(
        authority_id=authority_id("authority-tamper"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    with pytest.raises(TypeError):
        model.ObligationEvidenceIndex(case.obligation_index.cells)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        replace(case, case_id=authority_id("forged"))


def test_justification_foreign_premise_and_cycle_are_rejected() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "dag")
    key = model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING)
    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    values = dict(rule=model.UnflattenJustificationRule.UNIQUE_PHASE_BINDING,
                  premise_ids=(authority_id("not-in-inventory"),), conclusion=key,
                  polarity=model.EvidencePolarity.SUPPORTS, phase=phase)
    raw = object.__new__(model.AuthorityJustification)
    for name, value in values.items():
        object.__setattr__(raw, name, value)
    object.__setattr__(raw, "justification_id", "sha256:" + "0" * 64)
    from d810.transforms.unflatten_authority.ids import justification_id
    foreign = model.AuthorityJustification(justification_id=justification_id(raw), **values)
    with pytest.raises(ValueError, match="foreign"):
        from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
        _validate_justification_graph((foreign,), (key,), (), phase)


def test_metrics_and_view_counters_are_exact_and_preserved() -> None:
    metrics = model.PreparationBuildMetrics(1, 1, 4.5)
    assert metrics == model.PreparationBuildMetrics(1, 1, 4.5)
    for bad in ((0, 1, 1.0), (1, 2, 1.0), (1, 1, -1.0), (1, 1, float("inf"))):
        with pytest.raises((TypeError, ValueError)):
            model.PreparationBuildMetrics(*bad)
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "metrics")
    case = build_semantic_case(
        authority_id=authority_id("authority-metrics"), phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    from d810.transforms.unflatten_authority.views import view_metrics
    assert view_metrics(case).index_folds == 1
    assert view_metrics(case).view_graph_traversals == 0
    assert view_metrics(case).preparation_metrics == model.PreparationBuildMetrics(1, 1, 1.25)
    assert canonical_decode(canonical_bytes(case)).phase_metrics == case.phase_metrics


def test_preparation_receipt_is_hashed_and_closed() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "manifest")
    base = _complete_inputs(source_subjects=(entry,))
    with pytest.raises(ValueError, match="invalid record|receipt|token"):
        canonical_decode(canonical_bytes(base.preparation_receipt))
    values = {name: getattr(base.preparation_receipt, name) for name in base.preparation_receipt.__dataclass_fields__ if name not in {"receipt_id", "_token", "_minted"}}
    values["plan_input_digest"] = authority_id("omitted-plan-input")
    incomplete = replace(base, preparation_receipt=_receipt_fixture(**values))
    with pytest.raises(ValueError, match="receipt|plan input"):
        build_semantic_case(
            authority_id=authority_id("manifest-omission"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=incomplete,
        )


def test_topology_support_requires_named_reciprocal_peer_rows() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "topology-entry")
    peer = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "topology-peer")
    payload = model.TopologyEvidencePayload(
        entry.subject_id, (), (peer.subject_id,), True,
        canonical_authority_id(()), canonical_authority_id(()),
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY,
        entry, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    with pytest.raises(ValueError, match="edge relations"):
        build_semantic_case(
            authority_id=authority_id("topology-peer-missing"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(source_subjects=(entry, peer), lineage=(evidence,)),
        )


def test_patch_step_evidence_must_match_closed_step_inventory() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "patch-inventory")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    payload = model.PatchStepEvidencePayload(
        proposal.plan_id, 0, "PatchResegmentBlock", helper.block_ref,
        authority_id("patch-step"), helper.anchor_ea, 0x90, 4,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP,
        helper, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    values = {name: getattr(_complete_inputs(source_subjects=(entry,), candidate_subjects=(entry, helper), patch=(evidence,), proposal=proposal).preparation_receipt, name) for name in model.PreparationAuthorityReceipt.__dataclass_fields__ if name not in {"receipt_id", "_token", "_minted"}}
    values["patch_step_digest"] = authority_id("forged-step-copy")
    with pytest.raises(ValueError, match="receipt|patch"):
        build_semantic_case(
            authority_id=authority_id("patch-inventory-forged"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=replace(_complete_inputs(source_subjects=(entry,), candidate_subjects=(entry, helper), patch=(evidence,), proposal=proposal), preparation_receipt=_receipt_fixture(**values)),
        )


def test_empty_or_claim_only_inputs_cannot_build_an_accepted_authority() -> None:
    inputs = _complete_inputs(source_subjects=(), candidate_subjects=(), candidate_bindings=())
    with pytest.raises(ValueError, match="inventory|obligation|subject"):
        build_semantic_case(
            authority_id=authority_id("empty-authority"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )


def test_evidence_header_subject_and_phase_mismatch_is_rejected() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "header")
    other = _role_subject(model.SemanticSubjectRole.DISPATCHER_ENTRY, "foreign-header")
    payload = model.TopologyEvidencePayload(
        subject.subject_id, (), (), True, canonical_authority_id(()), canonical_authority_id(()),
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.TOPOLOGY, other,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    with pytest.raises(ValueError, match="foreign|subject|phase"):
        build_semantic_case(
            authority_id=authority_id("header-mismatch"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                inputs=_complete_inputs(source_subjects=(subject,), lineage=(evidence,)),
        )


def test_generic_gate_requires_exact_role_scope_and_multiple_rows() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "wrong-gate-role")
    gate = model.GenericCfgGateResult(
        model.GenericCfgGateKind.EFFECTFUL_REACHABILITY, True, (subject.subject_id,), (), "bad-role",
    )
    with pytest.raises(ValueError, match="gate|dimension|role"):
        build_semantic_case(
            authority_id=authority_id("wrong-gate-role"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(source_subjects=(subject,), gates=(gate,)),
        )


def test_public_decode_cannot_install_an_evaluator_owned_index() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "decode-index")
    case = build_semantic_case(
        authority_id=authority_id("decode-index"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    with pytest.raises(ValueError):
        canonical_decode(canonical_bytes(case.obligation_index))


def test_case_decode_recomputes_and_rejects_erased_index_cells() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "decode-case")
    case = build_semantic_case(
        authority_id=authority_id("decode-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    wire = json.loads(canonical_bytes(case).decode("ascii"))

    def erase_support(value: object) -> bool:
        if isinstance(value, dict) and value.get("t") == "record" and value.get("n") == "ObligationEvidenceIndex":
            for name, encoded in value["v"]:
                if name == "cells" and encoded["v"]:
                    for cell in encoded["v"]:
                        for cell_name, cell_value in cell["v"]:
                            if cell_name == "supporting_justification_ids" and cell_value["v"]:
                                cell_value["v"] = []
                                return True
        if isinstance(value, dict):
            return any(erase_support(item) for item in value.values())
        if isinstance(value, list):
            return any(erase_support(item) for item in value)
        return False

    assert erase_support(wire)
    with pytest.raises(ValueError, match="index|fold|record"):
        canonical_decode(json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii"))


def test_claim_without_correlated_typed_evidence_cannot_authorize_route() -> None:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    claim = proposal.claims[0]
    subjects = (
        _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "claim-only-entry"),
        claim.retired_route_subject, claim.source_subject, *claim.destination_subjects,
    )
    case = build_semantic_case(
        authority_id=authority_id("claim-only-route"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=subjects),
    )
    route_cells = tuple(
        cell for cell in case.obligation_index.cells
        if cell.key.dimension is model.SafetyDimension.ROUTE_EQUIVALENCE
    )
    assert route_cells and all(not cell.supporting_justification_ids for cell in route_cells)


def test_non_block_identity_requires_the_exact_candidate_subject() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "nonblock-entry")
    effect = _role_subject(model.SemanticSubjectRole.EFFECT_SITE, "nonblock-effect")
    case = build_semantic_case(
        authority_id=authority_id("nonblock-absence"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(entry, effect), candidate_subjects=(entry,)),
    )
    cell = next(
        item for item in case.obligation_index.cells
        if item.key == model.ObligationKey(effect, model.SafetyDimension.IDENTITY_BINDING)
    )
    assert cell.state is model.ObligationState.VIOLATED


def test_planned_helper_without_receipt_relation_gets_no_route_authority() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "helper-entry")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    case = build_semantic_case(
        authority_id=authority_id("helper-route"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(entry,), candidate_subjects=(entry, helper)),
    )
    helper_dimensions = {
        item.dimension for item in case.required_obligations if item.subject == helper
    }
    assert model.SafetyDimension.ROUTE_EQUIVALENCE not in helper_dimensions
    assert helper_dimensions == set(REQUIRED_DIMENSIONS[helper.role])


def test_stale_candidate_generation_precedes_obligation_reason() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "stale-generation")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    flow = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.VALUE_FLOW,
        role=model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
        block_ref=None, anchor_ea=None,
        locator=model.ValueFlowSubjectLocator(
            proposal.use_def_witness.fragment_id,
            proposal.use_def_witness.state_identity,
            proposal.plan_inputs.dispatcher_member_refs,
        ),
    )
    candidate_subjects = (entry, flow)
    inputs = _complete_inputs(
        source_subjects=(entry,), candidate_subjects=candidate_subjects,
        proposal=proposal,
    )
    stale_bindings = tuple(
        _binding(item.subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                 fingerprint=authority_id("stale-fingerprint"))
        for item in inputs.candidate_bindings
    )
    object.__setattr__(inputs, "candidate_bindings", stale_bindings)
    object.__setattr__(
        inputs.preparation_receipt, "candidate_binding_digest",
        _digest(tuple(sorted(stale_bindings, key=lambda item: item.subject.subject_id))),
    )
    object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))
    with pytest.raises(ValueError, match="binding|inventory"):
        build_semantic_case(
            authority_id=authority_id("stale-generation"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )


def test_producer_forecast_uses_source_fingerprint_and_source_binding_reason() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "producer-phase")
    base = _complete_inputs(source_subjects=(entry,))
    missing_source_bindings = tuple(
        _binding(
            subject, model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            fingerprint=authority_id("source-fp"), status=model.SubjectBindingStatus.MISSING,
        )
        for subject in base.source_subjects
    )
    phase_inputs = _complete_inputs(
        source_subjects=base.source_subjects,
        candidate_subjects=base.candidate_subjects,
        source_bindings=missing_source_bindings,
    )
    case = build_semantic_case(
        authority_id=authority_id("producer-phase"),
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        inputs=phase_inputs,
    )
    assert case.candidate_fingerprint == base.source_fingerprint
    assert case.candidate_generation == base.source_generation
    assert evaluate_case(case).reason is model.UnflattenAuthorityReason.SOURCE_BINDING_FAILED


def test_patch_step_wrong_plan_is_rejected_at_closed_boundary() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "patch-entry")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    payload = model.PatchStepEvidencePayload(
        authority_id("wrong-plan"), 0, "PatchRedirectBranch", helper.block_ref,
        authority_id("step"), None, None, None,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP,
        helper, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    with pytest.raises(ValueError, match="plan"):
        build_semantic_case(
            authority_id=authority_id("wrong-plan-case"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(entry,), candidate_subjects=(entry, helper),
                patch=(evidence,),
            ),
        )


def test_route_evidence_must_match_canonical_proof_scope() -> None:
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    claim = proposal.claims[0]
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "route-scope-entry")
    payload = model.SemanticRouteEvidencePayload(
        claim.retired_route_subject.subject_id,
        (authority_id("foreign-proof"),),
        claim.atomic_group_id,
        claim.source_subject.subject_id,
        tuple(item.subject_id for item in claim.destination_subjects),
        True,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.SEMANTIC_ROUTE,
        claim.retired_route_subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        payload,
    )
    with pytest.raises(ValueError, match="proof scope"):
        build_semantic_case(
            authority_id=authority_id("route-scope-case"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(entry, claim.retired_route_subject, claim.source_subject, *claim.destination_subjects),
                lineage=(evidence,),
            ),
        )


def test_rejected_result_variants_cannot_claim_accepted_or_empty_success() -> None:
    with pytest.raises(ValueError):
        model.UnflattenAuthorityVerdict(
            True, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            model.UnflattenAuthorityReason.ACCEPTED, authority_id("x"), None, None,
            authority_id("candidate"), None, (),
        )


def test_attached_rejection_must_report_exact_case_failures() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "verdict-failures")
    case = build_semantic_case(
        authority_id=authority_id("verdict-failures"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,), candidate_subjects=()),
    )
    expected = tuple(
        model.FailedObligation(cell.key, cell.state)
        for cell in case.obligation_index.cells
        if cell.state is not model.ObligationState.SATISFIED
    )
    with pytest.raises(ValueError, match="failed obligations"):
        model.UnflattenAuthorityVerdict(
            False, case.phase, model.UnflattenAuthorityReason.OBLIGATION_VIOLATED,
            case.authority_id, None, case.case_id, case.candidate_fingerprint,
            case, (),
        )
    verdict = model.UnflattenAuthorityVerdict(
        False, case.phase, model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED,
        case.authority_id, None, case.case_id, case.candidate_fingerprint,
        case, expected,
    )
    assert verdict.failed_obligations == expected


def test_case_decode_rejects_foreign_justification_premise() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "foreign-premise")
    case = build_semantic_case(
        authority_id=authority_id("foreign-premise-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    wire = json.loads(canonical_bytes(case).decode("ascii"))

    def corrupt(value: object) -> bool:
        if isinstance(value, dict) and value.get("t") == "record" and value.get("n") == "AuthorityJustification":
            for name, encoded in value["v"]:
                if name == "premise_ids":
                    encoded["v"] = [{"t": "str", "v": authority_id("foreign-premise-id")}]
                    return True
        if isinstance(value, dict):
            return any(corrupt(item) for item in value.values())
        if isinstance(value, list):
            return any(corrupt(item) for item in value)
        return False

    assert corrupt(wire)
    with pytest.raises(ValueError, match="premise|record"):
        canonical_decode(json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii"))


def test_case_decode_rejects_cross_phase_justification() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "cross-phase")
    case = build_semantic_case(
        authority_id=authority_id("cross-phase-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    wire = json.loads(canonical_bytes(case).decode("ascii"))

    def corrupt(value: object) -> bool:
        if isinstance(value, dict) and value.get("t") == "record" and value.get("n") == "AuthorityJustification":
            for name, encoded in value["v"]:
                if name == "phase":
                    encoded["v"] = {"t": "str", "v": "producer_forecast"}
                    return True
        if isinstance(value, dict):
            return any(corrupt(item) for item in value.values())
        if isinstance(value, list):
            return any(corrupt(item) for item in value)
        return False

    assert corrupt(wire)
    with pytest.raises(ValueError, match="phase|record"):
        canonical_decode(json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("ascii"))


def test_justification_rule_schema_rejects_wrong_dimension_polarity_and_scope() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "rule-schema")
    case = build_semantic_case(
        authority_id=authority_id("rule-schema"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    identity = next(
        item for item in case.justifications
        if item.conclusion == model.ObligationKey(subject, model.SafetyDimension.IDENTITY_BINDING)
    )
    for changes in (
        {"rule": model.UnflattenJustificationRule.SOURCE_PRESERVED},
        {"polarity": model.EvidencePolarity.REFUTES},
        {"premise_ids": ()},
    ):
        values = {
            name: getattr(identity, name)
            for name in identity.__dataclass_fields__ if name != "justification_id"
        }
        values.update(changes)
        forged = _justification_factory(model.AuthorityJustification, **values)
        with pytest.raises(ValueError, match="rule|dimension|polarity|premise|evidence"):
            from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
            _validate_justification_graph(
                (forged,), case.required_obligations, case.evidence, case.phase,
            )


def test_justification_ids_cannot_be_used_as_premises() -> None:
    subject = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "justification-premise")
    case = build_semantic_case(
        authority_id=authority_id("justification-premise"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(subject,)),
    )
    first, second = case.justifications[:2]
    values = {
        name: getattr(second, name)
        for name in second.__dataclass_fields__ if name != "justification_id"
    }
    values["premise_ids"] = (first.justification_id,)
    forged = _justification_factory(model.AuthorityJustification, **values)
    from d810.transforms.unflatten_authority.evaluate import _validate_justification_graph
    with pytest.raises(ValueError, match="premise"):
        _validate_justification_graph(
            (first, forged), case.required_obligations, case.evidence, case.phase,
        )


def test_split_and_fold_lineage_require_reciprocal_origin_witnesses() -> None:
    source = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "split-source")
    first = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "1")
    second = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "2")
    split = model.StructuralLineageEvidencePayload(
        source.subject_id, (first.subject_id, second.subject_id),
        model.StructuralDisposition.SPLIT, (), None,
    )
    split_evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
        source, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, split,
    )
    with pytest.raises(ValueError, match="reciprocal"):
        build_semantic_case(
            authority_id=authority_id("split-without-origin"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(source,), candidate_subjects=(source, first, second),
                lineage=(split_evidence,),
            ),
        )
    with pytest.raises(ValueError, match="folded|source group|origin"):
        folded = model.StructuralLineageEvidencePayload(
            source.subject_id, (first.subject_id,),
            model.StructuralDisposition.FOLDED, (0x1000, 0x1300), None,
        )
        folded_evidence = _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
            source, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, folded,
        )
        build_semantic_case(
            authority_id=authority_id("fold-with-origin"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(source,), candidate_subjects=(source, first),
                lineage=(folded_evidence,),
            ),
        )


def test_split_and_fold_lineage_use_exact_reciprocal_binding_eas() -> None:
    source = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "reciprocal-source")
    folded_source = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    first = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "1")
    second = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "2")
    split = model.StructuralLineageEvidencePayload(
        source.subject_id, (first.subject_id, second.subject_id),
        model.StructuralDisposition.SPLIT, (0x1000, 0x1100, 0x1300), None,
    )
    with pytest.raises(ValueError, match="folded|source group"):
        model.StructuralLineageEvidencePayload(
            folded_source.subject_id, (first.subject_id,),
            model.StructuralDisposition.FOLDED, (0x1300,), None,
        )
    with pytest.raises(ValueError, match="partition|origin"):
        build_semantic_case(
            authority_id=authority_id("forged-reciprocal"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=_complete_inputs(
                source_subjects=(source, folded_source),
                candidate_subjects=(source, folded_source, first, second),
                lineage=(_evidence_factory(
                    model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
                    source, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, split,
                ),),
            ),
        )


def test_fold_lineage_partitions_disjoint_source_origins_and_supports_each_member() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    first = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "0")
    second = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    baseline = _complete_inputs(source_subjects=(entry, first, second), candidate_subjects=(entry, first, second, helper))
    helper_binding = replace(
        next(item for item in baseline.candidate_bindings if item.subject == helper),
        native_instruction_eas=(first.anchor_ea, second.anchor_ea),
    )
    candidate_bindings = tuple(
        helper_binding if item.subject == helper else item
        for item in baseline.candidate_bindings
    )
    fold = model.StructuralLineageEvidencePayload(
        first.subject_id, (helper.subject_id,), model.StructuralDisposition.FOLDED,
        (first.anchor_ea, second.anchor_ea), None,
        source_subject_ids=(first.subject_id, second.subject_id),
    )
    fold_evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
        first, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, fold,
    )
    inputs = _complete_inputs(
        source_subjects=(entry, first, second),
        candidate_subjects=(entry, first, second, helper),
    )
    helper_block = next(
        block for block in inputs.candidate_inventory.blocks
        if block.serial == helper_binding.serial
    )
    helper_instructions = tuple(
        model.InventoryInstructionObservation(
            ordinal, ea, 0, 0, model.InsnKind.NOP, None, False, None,
        )
        for ordinal, ea in enumerate(helper_binding.native_instruction_eas)
    )
    object.__setattr__(
        inputs.candidate_inventory, "blocks",
        tuple(
            replace(
                block,
                native_instruction_eas=helper_binding.native_instruction_eas,
                instruction_observations=helper_instructions,
            ) if block is helper_block else block
            for block in inputs.candidate_inventory.blocks
        ),
    )
    object.__setattr__(inputs, "candidate_bindings", candidate_bindings)
    object.__setattr__(inputs.candidate_inventory, "bindings", candidate_bindings)
    object.__setattr__(inputs.preparation_receipt, "candidate_binding_digest", _digest(tuple(sorted(candidate_bindings, key=lambda item: item.subject.subject_id))))
    object.__setattr__(
        inputs.candidate_inventory, "inventory_digest",
        semantic_graph_inventory_digest(
            inputs.candidate_inventory.phase,
            inputs.candidate_inventory.graph_fingerprint,
            inputs.candidate_inventory.generation,
            inputs.candidate_inventory.blocks,
            inputs.candidate_inventory.subjects,
            inputs.candidate_inventory.bindings,
            inputs.candidate_inventory.effects,
            inputs.candidate_inventory.terminals,
            inputs.candidate_inventory.topology,
            inputs.candidate_inventory.reachable_serials,
            inputs.candidate_inventory.entry_serial,
            inputs.candidate_inventory.source_subject_ids,
        ),
    )
    object.__setattr__(inputs.preparation_receipt, "candidate_inventory_digest", inputs.candidate_inventory.inventory_digest)
    object.__setattr__(inputs.preparation_receipt, "receipt_id", receipt_id(inputs.preparation_receipt))
    object.__setattr__(inputs, "lineage_evidence", (fold_evidence,))
    with pytest.raises(ValueError, match="binding|inventory"):
        build_semantic_case(
            authority_id=authority_id("valid-fold-group"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            inputs=inputs,
        )
def test_effect_topology_is_conditional_on_exact_owner_survival() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "effect-entry")
    effect = _role_subject(model.SemanticSubjectRole.EFFECT_SITE, "1")
    case = build_semantic_case(
        authority_id=authority_id("effect-owner-absent"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, effect), candidate_subjects=(entry,),
        ),
    )
    dimensions = {
        key.dimension for key in case.required_obligations if key.subject == effect
    }
    assert model.SafetyDimension.TOPOLOGY_INTEGRITY not in dimensions
    assert next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(effect, model.SafetyDimension.IDENTITY_BINDING)
    ).state is model.ObligationState.VIOLATED


def test_local_alias_support_targets_exact_store_effect_relation() -> None:
    values = _valid_proposal(model)
    b0, b2 = block_ref("b0"), block_ref("b2")
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    owner = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=model.BlockSubjectLocator(b0, 0x1000),
    )
    store = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=model.EffectSubjectLocator(b0, 0x1000, 0x1000, model.EffectSiteKind.STORE),
    )
    route = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, block_ref=b0, anchor_ea=0x1000,
        locator=model.RouteSubjectLocator(authority_id("proof"), authority_id("group"), b0, 0x1000, (b2,), (0x1100,)),
    )
    destination = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    alias = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=owner, step_index=0, host_ea=0x1000, host_opcode=1,
        alias_token="alias", base_token="base", host_text_sha1=None, value_size=None,
        step_digest=authority_id("alias-step"), source_generation=3,
    )
    proposal = model.ProposedUnflattenContract(**values)
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    patch_payload = model.PatchStepEvidencePayload(
        proposal.plan_id, 0, "PatchScalarizeLocalAliasAccess", b0,
        alias.step_digest, 0x1000, 1, None,
    )
    patch_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP,
        helper, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, patch_payload,
    )
    effect_payload = model.EffectSiteEvidencePayload(
        store.subject_id, model.EffectSiteKind.STORE, 0x1000, 1, None, None, None,
        model.ProviderConsensusMode.NOT_APPLICABLE, (), True,
    )
    effect_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.EFFECT_SITE,
        store, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, effect_payload,
    )
    reach_payload = model.ReachabilityEvidencePayload(
        entry.subject_id, owner.subject_id, True, (entry.subject_id, owner.subject_id),
    )
    reach_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.REACHABILITY,
        owner, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, reach_payload,
    )
    relation = model.ConditionalSubjectRelation(
        owner.subject_id, store.subject_id, model.SafetyDimension.EFFECT_PRESERVATION,
        authority_id("alias-relation"),
    )
    inputs = _complete_inputs(
        source_subjects=(entry, owner, store, route, destination),
        candidate_subjects=(entry, owner, store, route, destination, helper),
        claims=(*proposal.claims, alias), proposal=proposal, patch=(patch_item,),
    )
    receipt_values = {
        name: getattr(inputs.preparation_receipt, name)
        for name in inputs.preparation_receipt.__dataclass_fields__
            if name not in {"receipt_id", "_minted"}
    }
    receipt_values["conditional_relation_digest"] = _digest((relation,))
    inputs = replace(
        inputs, conditional_relations=(relation,), lineage_evidence=(effect_item, reach_item),
        preparation_receipt=_receipt_fixture(**receipt_values),
    )
    case = build_semantic_case(
        authority_id=authority_id("valid-alias-relation"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, inputs=inputs,
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(store, model.SafetyDimension.EFFECT_PRESERVATION)
    )
    assert cell.state is model.ObligationState.SATISFIED

    wrong_store = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b2, anchor_ea=0x1100,
        locator=model.EffectSubjectLocator(b2, 0x1100, 0x1100, model.EffectSiteKind.STORE),
    )
    wrong_relation = model.ConditionalSubjectRelation(
        owner.subject_id, wrong_store.subject_id, model.SafetyDimension.EFFECT_PRESERVATION,
        authority_id("alias-wrong-owner"),
    )
    wrong_inputs = _complete_inputs(
        source_subjects=(entry, owner, wrong_store, route, destination),
        candidate_subjects=(entry, owner, wrong_store, route, destination, helper),
        claims=(*proposal.claims, alias), proposal=proposal, patch=(patch_item,),
    )
    wrong_effect_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.EFFECT_SITE, wrong_store,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.EffectSiteEvidencePayload(
            wrong_store.subject_id, model.EffectSiteKind.STORE, 0x1100, 1, None, None, None,
            model.ProviderConsensusMode.NOT_APPLICABLE, (), True,
        ),
    )
    wrong_receipt_values = {
        name: getattr(wrong_inputs.preparation_receipt, name)
        for name in wrong_inputs.preparation_receipt.__dataclass_fields__
            if name not in {"receipt_id", "_minted"}
    }
    wrong_receipt_values["conditional_relation_digest"] = _digest((wrong_relation,))
    wrong_inputs = replace(
        wrong_inputs, conditional_relations=(wrong_relation,),
        lineage_evidence=(wrong_effect_item, reach_item),
        preparation_receipt=_receipt_fixture(**wrong_receipt_values),
    )
    with pytest.raises(ValueError, match="exact STORE alias effect"):
        build_semantic_case(
            authority_id=authority_id("alias-wrong-owner-case"),
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, inputs=wrong_inputs,
        )


def test_local_alias_requires_endpoint_bearing_reachability_path() -> None:
    values = _valid_proposal(model)
    b0, b2 = block_ref("b0"), block_ref("b2")
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    owner = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=model.BlockSubjectLocator(b0, 0x1000),
    )
    store = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=model.EffectSubjectLocator(b0, 0x1000, 0x1000, model.EffectSiteKind.STORE),
    )
    route = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, block_ref=b0, anchor_ea=0x1000,
        locator=model.RouteSubjectLocator(authority_id("proof"), authority_id("group"), b0, 0x1000, (b2,), (0x1100,)),
    )
    destination = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    alias = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=owner, step_index=0, host_ea=0x1000, host_opcode=1,
        alias_token="alias", base_token="base", host_text_sha1=None, value_size=None,
        step_digest=authority_id("alias-step"), source_generation=3,
    )
    proposal = model.ProposedUnflattenContract(**values)
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    patch_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP, helper,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.PatchStepEvidencePayload(
            proposal.plan_id, 0, "PatchScalarizeLocalAliasAccess", b0,
            alias.step_digest, 0x1000, 1, None,
        ),
    )
    effect_item = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.EFFECT_SITE, store,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.EffectSiteEvidencePayload(
            store.subject_id, model.EffectSiteKind.STORE, 0x1000, 1, None, None, None,
            model.ProviderConsensusMode.NOT_APPLICABLE, (), True,
        ),
    )
    relation = model.ConditionalSubjectRelation(
        owner.subject_id, store.subject_id, model.SafetyDimension.EFFECT_PRESERVATION,
        authority_id("alias-relation-path"),
    )
    inputs = _complete_inputs(
        source_subjects=(entry, owner, store, route, destination),
        candidate_subjects=(entry, owner, store, route, destination, helper),
        claims=(*proposal.claims, alias), proposal=proposal, patch=(patch_item,),
    )
    receipt_values = {
        name: getattr(inputs.preparation_receipt, name)
        for name in inputs.preparation_receipt.__dataclass_fields__
        if name not in {"receipt_id", "_minted"}
    }
    receipt_values["conditional_relation_digest"] = _digest((relation,))
    bad_reach = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.REACHABILITY, owner,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.ReachabilityEvidencePayload(
            entry.subject_id, owner.subject_id, True, (entry.subject_id,),
        ),
    )
    inputs = replace(
        inputs, conditional_relations=(relation,),
        lineage_evidence=(effect_item, bad_reach),
        preparation_receipt=_receipt_fixture(**receipt_values),
    )
    case = build_semantic_case(
        authority_id=authority_id("alias-bad-path"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, inputs=inputs,
    )
    cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(store, model.SafetyDimension.EFFECT_PRESERVATION)
    )
    assert all(
        next(
            item for item in case.justifications
            if item.justification_id == justification_id
        ).rule is not model.UnflattenJustificationRule.LOCAL_ALIAS_SCALARIZATION_PROVEN
        for justification_id in cell.supporting_justification_ids
    )


def test_route_destination_reachability_correlates_handler_and_terminal_locators() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "route-entry")
    destination = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    handler = _role_subject(model.SemanticSubjectRole.AUTHORITATIVE_HANDLER, "2")
    terminal = _role_subject(model.SemanticSubjectRole.TERMINAL_SITE, "2")
    case = build_semantic_case(
        authority_id=authority_id("destination-conditionals"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(source_subjects=(entry, destination, handler, terminal)),
    )
    dimensions = {
        key.dimension for key in case.required_obligations if key.subject == destination
    }
    assert {
        model.SafetyDimension.HANDLER_REACHABILITY,
        model.SafetyDimension.TERMINAL_REACHABILITY,
    } <= dimensions

    reachability = model.ReachabilityEvidencePayload(
        entry.subject_id, destination.subject_id, True,
        (entry.subject_id, destination.subject_id),
    )
    reachability_evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.REACHABILITY,
        destination, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, reachability,
    )
    satisfied_case = build_semantic_case(
        authority_id=authority_id("destination-reachability"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, destination, handler, terminal),
            lineage=(reachability_evidence,),
        ),
    )
    for subject, dimension in (
        (destination, model.SafetyDimension.HANDLER_REACHABILITY),
        (destination, model.SafetyDimension.TERMINAL_REACHABILITY),
        (handler, model.SafetyDimension.HANDLER_REACHABILITY),
        (terminal, model.SafetyDimension.TERMINAL_REACHABILITY),
    ):
        assert next(
            cell for cell in satisfied_case.obligation_index.cells
            if cell.key == model.ObligationKey(subject, dimension)
        ).state is model.ObligationState.SATISFIED


def test_retirement_claim_requires_one_authorized_lineage_per_member() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "retirement-entry")
    member0 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "0")
    member1 = _role_subject(model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE, "1")
    corridor_locator = model.CorridorSubjectLocator(
        authority_id("retired-corridor"), member0.block_ref, member0.anchor_ea,
        (member0.block_ref, member1.block_ref),
        (member0.anchor_ea, member1.anchor_ea),
    )
    corridor = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.CORRIDOR,
        role=model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=member0.block_ref, anchor_ea=member0.anchor_ea,
        locator=corridor_locator,
    )
    retirement = _claim_factory(
        model.RetiredDispatcherInfrastructureClaim,
        kind=model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        infrastructure_subject=member0, corridor_subject=corridor,
        member_subjects=(member0, member1),
        retirement_proof_ids=(authority_id("retirement-proof"),), source_generation=3,
    )

    def lineage(member: model.SemanticSubjectRef) -> model.AuthorityEvidence:
        payload = model.StructuralLineageEvidencePayload(
            member.subject_id, (), model.StructuralDisposition.AUTHORIZED_RETIREMENT,
            (), retirement.claim_id,
        )
        return _evidence_factory(
            model.AuthorityEvidence, model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE,
            member, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
        )

    coverage_payload = model.CorridorCoverageEvidencePayload(
        corridor.subject_id, (member0.subject_id, member1.subject_id),
        (member0.subject_id, member1.subject_id), (),
    )
    coverage = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.CORRIDOR_COVERAGE,
        corridor, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, coverage_payload,
    )
    proposal_values = _valid_proposal(model)
    route_proposal_claim = proposal_values["claims"][0]
    proposal_values["plan_inputs"] = replace(
        proposal_values["plan_inputs"],
        shape=model.UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT,
    )
    retirement_proposal = model.ProposedUnflattenContract(
        **{**proposal_values, "claims": (retirement,)}
    )
    complete = build_semantic_case(
        authority_id=authority_id("retirement-complete"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(
                entry, member0, member1, corridor,
                route_proposal_claim.retired_route_subject,
                route_proposal_claim.replacement_route_subject,
                route_proposal_claim.source_subject,
                *route_proposal_claim.destination_subjects,
            ),
            lineage=(lineage(member0), lineage(member1), coverage),
            claims=(retirement,), proposal=retirement_proposal,
        ),
    )
    assert next(
        cell for cell in complete.obligation_index.cells
        if cell.key == model.ObligationKey(member0, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    ).state is model.ObligationState.SATISFIED
    incomplete = build_semantic_case(
        authority_id=authority_id("retirement-incomplete"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(
                entry, member0, member1, corridor,
                route_proposal_claim.retired_route_subject,
                route_proposal_claim.replacement_route_subject,
                route_proposal_claim.source_subject,
                *route_proposal_claim.destination_subjects,
            ),
            lineage=(lineage(member0), coverage),
            claims=(retirement,), proposal=retirement_proposal,
        ),
    )
    assert next(
        cell for cell in incomplete.obligation_index.cells
        if cell.key == model.ObligationKey(member1, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    ).state is model.ObligationState.VIOLATED


def test_resegmentation_patch_step_supports_only_its_helper_structural_key() -> None:
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "resegment-entry")
    helper = _role_subject(model.SemanticSubjectRole.PLANNED_HELPER, "0")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    payload = model.PatchStepEvidencePayload(
        proposal.plan_id, 0, "PatchResegmentBlock", helper.block_ref,
        authority_id("resegment-step"), helper.anchor_ea, 0x90, 4,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.PATCH_STEP,
        helper, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, payload,
    )
    case = build_semantic_case(
        authority_id=authority_id("resegment-case"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry,), candidate_subjects=(entry, helper),
            patch=(evidence,), proposal=proposal,
        ),
    )
    helper_cell = next(
        cell for cell in case.obligation_index.cells
        if cell.key == model.ObligationKey(helper, model.SafetyDimension.STRUCTURAL_ACCOUNTING)
    )
    assert helper_cell.state is model.ObligationState.SATISFIED
    for item in case.obligation_index.cells:
        if item.key.subject == helper and item.key.dimension is not model.SafetyDimension.STRUCTURAL_ACCOUNTING:
            assert all(
                next(j for j in case.justifications if j.justification_id == jid).rule
                is not model.UnflattenJustificationRule.RESEGMENTATION_LINEAGE_PROVEN
                for jid in item.supporting_justification_ids
            )


def test_exact_infeasible_effect_authorizes_classified_discarded_loss() -> None:
    b0, b2 = block_ref("b0"), block_ref("b2")
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "0")
    source = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "0")
    predicate = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, "0")
    selected = _role_subject(model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION, "2")
    discarded_locator = model.EffectSubjectLocator(b0, 0x1000, 0x1008, model.EffectSiteKind.STORE)
    discarded = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE, block_ref=b0, anchor_ea=0x1000,
        locator=discarded_locator,
    )
    effect = discarded
    claim = _claim_factory(
        model.ExactInfeasibleEffectClaim,
        kind=model.UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT,
        effect_subject=effect, source_subject=source, predicate_subject=predicate,
        selected_target_subject=selected, discarded_effect_subject=discarded,
        normalized_state=1, state_identity=state_identity(), width=4,
        source_write_ea=0x1004, predicate_branch_ea=0x1006,
        discarded_effect_ea=0x1008, selected_edge_role=edge_role(),
        route_proof_ids=(authority_id("proof"),),
        consensus=model.ProviderConsensusWitness(
            model.ProviderConsensusMode.NOT_APPLICABLE, (),
        ), source_generation=3,
    )
    route_locator = model.RouteSubjectLocator(
        authority_id("proof"), authority_id("group"), b0, 0x1000,
        (b2,), (0x1100,),
    )
    route = _subject_factory(
        model.SemanticSubjectRef, kind=model.SemanticSubjectKind.ROUTE,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
            block_ref=b0, anchor_ea=0x1000, locator=route_locator,
    )
    effect_payload = model.EffectSiteEvidencePayload(
        discarded.subject_id, model.EffectSiteKind.STORE, 0x1008, 0x90, 4,
        state_identity(), 1, model.ProviderConsensusMode.NOT_APPLICABLE, (), False,
    )
    effect_evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.EFFECT_SITE,
        discarded, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, effect_payload,
    )
    route_payload = model.SemanticRouteEvidencePayload(
        route.subject_id, (authority_id("proof"),), authority_id("group"),
            predicate.subject_id, (selected.subject_id,), True,
    )
    route_evidence = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.SEMANTIC_ROUTE,
        route, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, route_payload,
    )
    proposal_values = _valid_proposal(model)
    catalog = proposal_values["source_identity_catalog"]
    proposal_values["source_identity_catalog"] = replace(
        catalog,
        blocks=(
                replace(catalog.blocks[0], native_instruction_eas=(0x1000, 0x1004, 0x1006, 0x1008)),
                replace(catalog.blocks[1], native_instruction_eas=(0x1300,)),
            catalog.blocks[2],
        ),
    )
    proposal_values["plan_inputs"] = replace(
        proposal_values["plan_inputs"], shape=model.UnflattenPlanShape.EXACT_EFFECT_ONLY,
    )
    proposal = model.ProposedUnflattenContract(
        **{**proposal_values, "claims": (claim,)}
    )
    case = build_semantic_case(
        authority_id=authority_id("exact-effect-loss"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, source, predicate, selected, effect, discarded, route),
            lineage=(effect_evidence, route_evidence),
            claims=(claim,), proposal=proposal,
        ),
    )
    for dimension in (
        model.SafetyDimension.EFFECT_PRESERVATION,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING,
    ):
        cell = next(
            cell for cell in case.obligation_index.cells
            if cell.key == model.ObligationKey(discarded, dimension)
        )
        assert cell.state is model.ObligationState.SATISFIED
        assert not cell.refuting_justification_ids
    failed_effect_gate = model.GenericCfgGateResult(
        model.GenericCfgGateKind.EFFECTFUL_REACHABILITY, False, (),
        (discarded.subject_id,), "classified-loss",
    )
    failed_gate_case = build_semantic_case(
        authority_id=authority_id("exact-effect-failed-generic-gate"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, source, predicate, selected, effect, discarded, route),
            lineage=(effect_evidence, route_evidence), claims=(claim,), proposal=proposal,
            gates=(failed_effect_gate,),
        ),
    )
    failed_cell = next(
        cell for cell in failed_gate_case.obligation_index.cells
        if cell.key == model.ObligationKey(discarded, model.SafetyDimension.EFFECT_PRESERVATION)
    )
    assert failed_cell.state is model.ObligationState.SATISFIED
    assert not failed_cell.refuting_justification_ids
    assert any(
        type(item.payload) is model.GenericCfgGateEvidencePayload
        and not item.payload.passed
        and discarded.subject_id in item.payload.affected_subject_ids
        for item in failed_gate_case.evidence
    )
    assert sum(
        item.rule is model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN
        for item in failed_gate_case.justifications
    ) == 2
    assert not any(
        item.rule is model.UnflattenJustificationRule.GENERIC_CFG_GATE_FAILED
        and item.conclusion.subject.subject_id == discarded.subject_id
        for item in failed_gate_case.justifications
    )
    from d810.transforms.unflatten_authority.views import exact_effect_loss_view
    loss_view = exact_effect_loss_view(failed_gate_case, discarded.subject_id)
    assert loss_view.evidence_ids
    assert len(loss_view.justification_ids) == 2
    exact_justifications = tuple(
        item for item in failed_gate_case.justifications
        if item.rule is model.UnflattenJustificationRule.EXACT_INFEASIBLE_EFFECT_PROVEN
    )
    assert {
        item.conclusion.subject.subject_id for item in exact_justifications
    } == {discarded.subject_id}
    assert {
        item.conclusion.dimension for item in exact_justifications
    } == {
        model.SafetyDimension.EFFECT_PRESERVATION,
        model.SafetyDimension.STRUCTURAL_ACCOUNTING,
    }
    forbidden_roles = {
        model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        model.SemanticSubjectRole.TERMINAL_SITE,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
    }
    assert not any(item.conclusion.subject.role in forbidden_roles for item in exact_justifications)
    bad_effect = _evidence_factory(
        model.AuthorityEvidence, model.AuthorityEvidenceKind.EFFECT_SITE,
        discarded, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        replace(effect_payload, width=8),
    )
    bad_case = build_semantic_case(
        authority_id=authority_id("exact-effect-width-mismatch"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        inputs=_complete_inputs(
            source_subjects=(entry, source, predicate, selected, effect, discarded, route),
            lineage=(bad_effect, route_evidence),
            claims=(claim,), proposal=proposal,
        ),
    )
    assert next(
        cell for cell in bad_case.obligation_index.cells
        if cell.key == model.ObligationKey(discarded, model.SafetyDimension.EFFECT_PRESERVATION)
    ).state is model.ObligationState.INCONSISTENT
