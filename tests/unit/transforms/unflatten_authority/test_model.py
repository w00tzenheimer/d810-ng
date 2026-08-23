"""Characterize the closed authority-model package boundary."""

from __future__ import annotations

from dataclasses import is_dataclass, replace
import inspect

import pytest

from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.analyses.control_flow.semantic_route_evidence import (
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
)
from .helpers import import_authority_model
from .helpers import authority_id, block_ref, edge_role, state_identity
from d810.transforms.unflatten_authority.ids import _subject_factory, _claim_factory, _evidence_factory, subject_id, authority_id as canonical_authority_id, canonical_bytes
from d810.transforms.unflatten_authority.legacy_wire import encode_legacy_value


def _retirement_catalog(model, refs, anchors, generation=3):
    canonical_payload = encode_legacy_value({
        "family": "retired_infrastructure",
        "source_generation": generation,
        "members": tuple({
            "ref": canonical_bytes(ref), "anchor_ea": anchor,
            "retired": True, "role": "comparison_dispatcher",
        } for ref, anchor in zip(refs, anchors)),
        "family_payload": {
            "retired_infrastructure": tuple({
                "role": "comparison_dispatcher",
                "anchor_ea": anchor,
                "retired": True,
            } for anchor in anchors),
        },
    })
    roles = tuple("comparison_dispatcher" for _ in refs)
    proof = model.RetirementProofRecord(
        canonical_authority_id(("unflatten.retirement-proof.v3", canonical_payload)),
        model.RetirementProofFamily.RETIRED_INFRASTRUCTURE,
        canonical_payload, tuple(refs), tuple(anchors), generation, roles,
    )
    rows = tuple(
        model.RetirementMemberCatalogRow(ref, anchor, (anchor,), generation, True, (proof,))
        for ref, anchor in zip(refs, anchors)
    )
    return model.RetirementAuthorityCatalog(
        canonical_authority_id(("unflatten.retirement-catalog.v1", generation, rows, (proof,))),
        generation, rows, (proof,),
    )


def _subject(model, kind, role, locator):
    owner = (
        getattr(locator, "block_ref", None)
        or getattr(locator, "source_ref", None)
        or getattr(locator, "owner_ref", None)
        or getattr(locator, "entry_ref", None)
    )
    anchor = (
        getattr(locator, "anchor_ea", None)
        or getattr(locator, "source_anchor_ea", None)
        or getattr(locator, "owner_anchor_ea", None)
        or getattr(locator, "entry_anchor_ea", None)
    )
    if kind is model.SemanticSubjectKind.VALUE_FLOW:
        owner = anchor = None
    return _subject_factory(
        model.SemanticSubjectRef,
        kind=kind,
        role=role,
        block_ref=owner,
        anchor_ea=anchor,
        locator=locator,
    )


def _reissued_claim(claim, **changes):
    payload = {
        name: getattr(claim, name)
        for name in claim.__dataclass_fields__
        if name != "claim_id"
    }
    payload.update(changes)
    return _claim_factory(type(claim), **payload)


class _RefSubclass:
    pass


def _native_key(model, *, fingerprint="f"):
    return model.NativePreanalysisKey(
        "input", "x86", 64, 0, fingerprint * 64, "p" * 64, "s" * 64,
    )


def _canonical_evidence(model, *, generation=3, native_key=None):
    native_key = native_key or _native_key(model)
    identity = StableBlockIdentity.from_instruction_eas(
        [0x1000], native_key=native_key,
    )
    target_identity = StableBlockIdentity.from_instruction_eas(
        [0x1100], native_key=native_key,
    )
    destination = SemanticRouteDestination(
        model.SemanticEdgeRole.DIRECT, 1, target_identity, 0x1100,
    )
    proof = SemanticRouteProof(
        authority_id("proof"), authority_id("group"),
        SemanticRouteProofKind.BOOTSTRAP, SemanticRouteShape.DIRECT,
        identity, 0x1000, (destination,), NativeEaInterval(0x1000, 0x1001),
    )
    return model.CanonicalSemanticEvidence(
        native_key, generation, authority_id("group"), (proof,),
    ), identity


def _valid_proposal(model):
    b0, b1, b2 = block_ref("b0"), block_ref("b1"), block_ref("b2")
    route_evidence, _ = _canonical_evidence(model)
    route_locator = model.RouteSubjectLocator(
        authority_id("proof"), authority_id("group"), b0, 0x1000,
        (b2,), (0x1100,),
    )
    replacement_locator = model.RouteSubjectLocator(
        authority_id("proof"), authority_id("group"), b0, 0x1000,
        (b2,), (0x1100,),
    )
    retired_route = _subject(model, model.SemanticSubjectKind.ROUTE,
                             model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                             route_locator)
    replacement_route = _subject(model, model.SemanticSubjectKind.ROUTE,
                                 model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                                 replacement_locator)
    source = _subject(model, model.SemanticSubjectKind.BLOCK,
                      model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                      model.BlockSubjectLocator(b0, 0x1000))
    destination = _subject(model, model.SemanticSubjectKind.BLOCK,
                           model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
                           model.BlockSubjectLocator(b2, 0x1100))
    claim = _claim_factory(model.EquivalentSemanticRouteClaim,
        model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
        retired_route, replacement_route, source, (destination,),
        (authority_id("proof"),), authority_id("group"), 3,
    )
    key = route_evidence.native_key
    catalog = model.SourceIdentityCatalog(
        key, 3, (
            model.SourceBlockIdentityWitness(b0, 0x1000, (0x1000,)),
            model.SourceBlockIdentityWitness(b1, 0x1300, (0x1300,)),
            model.SourceBlockIdentityWitness(b2, 0x1100, (0x1100,)),
        ),
    )
    plan_inputs = model.UnflattenPlanInputCatalog(
        model.UnflattenPlanShape.PARTIAL_REWRITE, b0, b0, (b0, b1),
        (model.AuthoritativeHandlerInput(b2, 0x1100, (1,)),), state_identity(),
    )
    witness = model.UseDefFragmentWitness(
        authority_id("fragment"), state_identity(), (b0,), authority_id("redirect"),
        True, True, 0, (),
    )
    return dict(
        schema_version=1, rule_set_version=1, plan_id=authority_id("plan"),
        route_evidence=route_evidence, source_identity_catalog=catalog,
        use_def_witness=witness, claims=(claim,), plan_inputs=plan_inputs,
    )


def _minimal_corridor_forecast(model, proposal):
    """Build a minimal typed PATH-domain forecast for retirement fixtures."""

    dispatcher_ref = proposal.plan_inputs.dispatcher_entry_ref
    dispatcher = next(
        item for item in proposal.source_identity_catalog.blocks
        if item.block_ref == dispatcher_ref
    )
    source = next(
        item for item in proposal.source_identity_catalog.blocks
        if item.block_ref != dispatcher_ref
    )
    nodes = (
        model.CorridorCoveragePathNode(source.block_ref, source.anchor_ea),
        model.CorridorCoveragePathNode(dispatcher_ref, dispatcher.anchor_ea),
    )
    path_id = canonical_authority_id((
        "unflatten.corridor-coverage-path.v1", nodes, None,
        model.CorridorPathDisposition.STRUCTURALLY_COVERED, (),
    ))
    path = model.CorridorCoveragePath(
        path_id, nodes, None, model.CorridorPathDisposition.STRUCTURALLY_COVERED, (),
    )
    forecast_id = canonical_authority_id((
        "unflatten.corridor-coverage-forecast.v1", proposal.plan_id,
        dispatcher.anchor_ea, proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation, dispatcher_ref,
        dispatcher.anchor_ea, (path,), (path_id,), (), True, (), (), (),
    ))
    return model.CorridorCoverageForecast(
        forecast_id, proposal.plan_id, dispatcher.anchor_ea,
        proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation, dispatcher_ref,
        dispatcher.anchor_ea, (path,), (path_id,), (), True, (), (), (),
    )


def test_authority_model_package_exists_and_is_closed() -> None:
    """The model package is the only import surface for typed authority data."""

    model = import_authority_model()

    assert model.__all__
    assert all(isinstance(name, str) for name in model.__all__)


def test_subject_kind_role_locator_matrix_is_closed() -> None:
    model = import_authority_model()
    b0 = block_ref("b0")
    b1 = block_ref("b1")
    cases = [
        (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY,
         model.BlockSubjectLocator(b0, 0x1000)),
        (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.DISPATCHER_ENTRY,
         model.BlockSubjectLocator(b0, 0x1000)),
        (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
         model.BlockSubjectLocator(b0, 0x1000)),
        (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
         model.BlockSubjectLocator(b0, 0x1000)),
        (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
         model.BlockSubjectLocator(b0, 0x1000)),
        (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.EFFECT_SITE,
         model.BlockSubjectLocator(b0, 0x1000)),
        (model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.PLANNED_HELPER,
         model.BlockSubjectLocator(b0, 0x1000)),
        (model.SemanticSubjectKind.EDGE, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
         model.EdgeSubjectLocator(b0, 0x1000, b1, 0x1100, edge_role())),
        (model.SemanticSubjectKind.ROUTE, model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
         model.RouteSubjectLocator(authority_id("p"), authority_id("g"), b0, 0x1000, (b1,), (0x1100,))),
        (model.SemanticSubjectKind.EFFECT, model.SemanticSubjectRole.EFFECT_SITE,
         model.EffectSubjectLocator(b0, 0x1000, 0x1004, model.EffectSiteKind.STORE)),
        (model.SemanticSubjectKind.HANDLER, model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
         model.HandlerSubjectLocator(b0, 0x1000, (1, 2))),
        (model.SemanticSubjectKind.TERMINAL, model.SemanticSubjectRole.TERMINAL_SITE,
         model.TerminalSubjectLocator(b0, 0x1000, model.TerminalKind.RETURN, 0x1004)),
        (model.SemanticSubjectKind.VALUE_FLOW, model.SemanticSubjectRole.NON_STATE_VALUE_FLOW,
         model.ValueFlowSubjectLocator(authority_id("f"), state_identity(), (b0,))),
        (model.SemanticSubjectKind.CORRIDOR, model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
         model.CorridorSubjectLocator(authority_id("c"), b0, 0x1000, (b0, b1), (0x1000, 0x1100))),
    ]
    for index, (kind, role, locator) in enumerate(cases):
        owner = (
            getattr(locator, "block_ref", None)
            or getattr(locator, "source_ref", None)
            or getattr(locator, "owner_ref", None)
            or getattr(locator, "entry_ref", None)
        )
        anchor = getattr(locator, "anchor_ea", None)
        anchor = anchor if anchor is not None else getattr(locator, "source_anchor_ea", None)
        anchor = anchor if anchor is not None else getattr(locator, "owner_anchor_ea", None)
        anchor = anchor if anchor is not None else getattr(locator, "entry_anchor_ea", None)
        subject = model.SemanticSubjectRef(
            kind=kind, role=role, subject_id=subject_id(kind, role, locator),
            block_ref=None if kind is model.SemanticSubjectKind.VALUE_FLOW else owner,
            anchor_ea=None if kind is model.SemanticSubjectKind.VALUE_FLOW else anchor,
            locator=locator,
        )
        assert subject.locator is locator

    with pytest.raises(ValueError, match="^unsupported subject kind/role/locator$"):
        model.SemanticSubjectRef(
            kind=model.SemanticSubjectKind.EFFECT,
            role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
            subject_id=authority_id("z"), block_ref=b0, anchor_ea=0x1000,
            locator=model.EffectSubjectLocator(b0, 0x1000, 0x1004, model.EffectSiteKind.STORE),
        )


def test_model_dataclasses_are_frozen_and_slotted() -> None:
    model = import_authority_model()
    for name in model.__all__:
        value = getattr(model, name)
        if is_dataclass(value):
            assert getattr(value, "__slots__", None) is not None
            assert getattr(value, "__dataclass_params__").frozen


def test_derived_inputs_exposes_only_transaction_facts() -> None:
    model = import_authority_model()
    fields = set(inspect.signature(model.DerivedUnflattenPreparationInputs).parameters)
    assert fields == {
        "proposal", "claims", "preparation_receipt", "source_inventory",
        "candidate_inventory", "source_route_assessment",
        "candidate_route_assessment", "generic_gate_facts",
            "conditional_relations", "patch_step_facts", "preparation_metrics",
            "phase_build_metrics", "corridor_coverage_phase_result",
            "terminal_cycle_phase_results",
    }
    for removed in (
        "source_subjects", "candidate_subjects", "source_bindings",
        "candidate_bindings", "source_fingerprint", "candidate_fingerprint",
        "source_generation", "candidate_generation", "lineage_evidence",
        "patch_step_evidence", "generic_gates",
    ):
        assert removed not in fields


def _terminal_cycle_phase_result(model):
    residue = (block_ref("b0"), block_ref("b1"))
    source_edges = ((residue[0], residue[1]), (residue[1], residue[0]))
    candidate_edges = ((residue[0], residue[1]),)
    route = (block_ref("z-carrier"), block_ref("a-terminal"))
    cycle_subject = _subject(
        model, model.SemanticSubjectKind.CORRIDOR,
        model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
        model.CorridorSubjectLocator(
            authority_id("terminal-cycle-corridor"), residue[0], 0x1000,
            residue, (0x1000, 0x1100),
        ),
    )
    cleanup_subject = _subject(
        model, model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        model.BlockSubjectLocator(residue[1], 0x1100),
    )
    carrier_subject = _subject(
        model, model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        model.BlockSubjectLocator(route[0], 0x1900),
    )
    terminal_subject = _subject(
        model, model.SemanticSubjectKind.TERMINAL,
        model.SemanticSubjectRole.TERMINAL_SITE,
        model.TerminalSubjectLocator(route[1], 0x2000, model.TerminalKind.STOP, 0x2000),
    )
    residue_subject = _subject(
        model, model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        model.BlockSubjectLocator(residue[0], 0x1000),
    )
    subjects = (cycle_subject, cleanup_subject, carrier_subject, terminal_subject, residue_subject)
    bound_subject_ids = tuple(sorted(subject.subject_id for subject in subjects))
    source_fingerprint = authority_id("terminal-cycle-source")
    candidate_fingerprint = authority_id("terminal-cycle-candidate")
    def bindings(phase, fingerprint, generation, serial_offset):
        return tuple(sorted((
            model.PhaseSubjectBinding(
                subject, phase, subject.block_ref, fingerprint, generation,
                model.SubjectBindingStatus.UNIQUE, serial_offset + index,
                subject.anchor_ea, (subject.anchor_ea,), subject.role,
            )
            for index, subject in enumerate(subjects)
        ), key=lambda item: item.subject.subject_id))
    source_bindings = bindings(model.UnflattenAuthorityPhase.PRODUCER_FORECAST, source_fingerprint, 3, 0)
    candidate_bindings = bindings(model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, candidate_fingerprint, 7, 10)
    fields = dict(
        claim_id=authority_id("terminal-cycle-claim"),
        terminal_route_proof_id=authority_id("terminal-cycle-proof"),
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        source_fingerprint=source_fingerprint,
        candidate_fingerprint=candidate_fingerprint,
        source_generation=3,
        candidate_generation=7,
        bound_subject_ids=bound_subject_ids,
        source_binding_digest=canonical_authority_id(source_bindings),
        candidate_binding_digest=canonical_authority_id(candidate_bindings),
        residue_refs=residue,
        source_cycle_edges=source_edges,
        candidate_cycle_edges=candidate_edges,
        source_bindings=source_bindings,
        candidate_bindings=candidate_bindings,
        terminal_source_ref=block_ref("bsource"),
        cleanup_source_ref=residue[1],
        terminal_carrier_ref=route[0],
        terminal_route_refs=route,
        terminal_subject_id=terminal_subject.subject_id,
        terminal_subject_ref=route[-1],
    )
    result_id = canonical_authority_id((
        "unflatten.terminal-cycle-phase.v1", fields["claim_id"],
        fields["terminal_route_proof_id"], fields["phase"],
        fields["source_fingerprint"], fields["candidate_fingerprint"],
        fields["source_generation"], fields["candidate_generation"],
        fields["bound_subject_ids"], fields["source_binding_digest"],
        fields["candidate_binding_digest"], fields["residue_refs"],
        fields["source_cycle_edges"], fields["candidate_cycle_edges"],
        fields["terminal_source_ref"], fields["cleanup_source_ref"],
        fields["terminal_carrier_ref"], fields["terminal_route_refs"],
        fields["terminal_subject_id"], fields["terminal_subject_ref"],
    ))
    return model.TerminalCyclePhaseResult(
        result_id=result_id,
        **fields,
    )


def test_terminal_cycle_phase_result_recomputes_id_and_allows_independent_generations() -> None:
    model = import_authority_model()
    result = _terminal_cycle_phase_result(model)
    assert result.source_generation == 3
    assert result.candidate_generation == 7
    with pytest.raises(ValueError, match="result_id|source bindings"):
        replace(result, source_fingerprint=authority_id("drifted"))


def test_terminal_cycle_phase_result_preserves_route_path_order() -> None:
    model = import_authority_model()
    result = _terminal_cycle_phase_result(model)
    # The carrier/terminal path is intentionally not structural-ref order.
    assert result.terminal_route_refs == (
        block_ref("z-carrier"),
        block_ref("a-terminal"),
    )


def test_terminal_cycle_phase_result_rejects_foreign_cycle_edges() -> None:
    model = import_authority_model()
    result = _terminal_cycle_phase_result(model)
    foreign = block_ref("foreign")
    with pytest.raises(ValueError, match="edge endpoints"):
        model.TerminalCyclePhaseResult(
            **{
                **{name: getattr(result, name) for name in result.__dataclass_fields__ if name != "result_id"},
                "result_id": canonical_authority_id((
                    "unflatten.terminal-cycle-phase.v1", result.claim_id,
                    result.terminal_route_proof_id, result.phase,
                    result.source_fingerprint, result.candidate_fingerprint,
                    result.source_generation, result.candidate_generation,
                    result.bound_subject_ids, result.source_binding_digest,
                    result.candidate_binding_digest, result.residue_refs,
                    ((foreign, result.residue_refs[0]),), result.candidate_cycle_edges,
                    result.terminal_source_ref, result.cleanup_source_ref,
                    result.terminal_carrier_ref, result.terminal_route_refs,
                    result.terminal_subject_id, result.terminal_subject_ref,
                )),
                "source_cycle_edges": ((foreign, result.residue_refs[0]),),
            }
        )


def test_terminal_cycle_evidence_payload_is_registered_and_result_bound() -> None:
    model = import_authority_model()
    result = _terminal_cycle_phase_result(model)
    payload = model.TerminalCycleEvidencePayload(
        phase_result_id=result.result_id,
        claim_id=result.claim_id,
        terminal_route_proof_id=result.terminal_route_proof_id,
        phase=result.phase,
        source_fingerprint=result.source_fingerprint,
        candidate_fingerprint=result.candidate_fingerprint,
        source_generation=result.source_generation,
        candidate_generation=result.candidate_generation,
        bound_subject_ids=result.bound_subject_ids,
        source_binding_digest=result.source_binding_digest,
        candidate_binding_digest=result.candidate_binding_digest,
        residue_refs=result.residue_refs,
        source_cycle_edges=result.source_cycle_edges,
        candidate_cycle_edges=result.candidate_cycle_edges,
        source_bindings=result.source_bindings,
        candidate_bindings=result.candidate_bindings,
        terminal_source_ref=result.terminal_source_ref,
        cleanup_source_ref=result.cleanup_source_ref,
        terminal_carrier_ref=result.terminal_carrier_ref,
        terminal_route_refs=result.terminal_route_refs,
        terminal_subject_id=result.terminal_subject_id,
        terminal_subject_ref=result.terminal_subject_ref,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence,
        model.AuthorityEvidenceKind.TERMINAL_CYCLE,
        result.source_bindings[0].subject,
        result.phase,
        payload,
    )
    assert evidence.payload is payload


def _terminal_cycle_evidence_payload(model, result):
    return model.TerminalCycleEvidencePayload(
        phase_result_id=result.result_id,
        claim_id=result.claim_id,
        terminal_route_proof_id=result.terminal_route_proof_id,
        phase=result.phase,
        source_fingerprint=result.source_fingerprint,
        candidate_fingerprint=result.candidate_fingerprint,
        source_generation=result.source_generation,
        candidate_generation=result.candidate_generation,
        bound_subject_ids=result.bound_subject_ids,
        source_binding_digest=result.source_binding_digest,
        candidate_binding_digest=result.candidate_binding_digest,
        residue_refs=result.residue_refs,
        source_cycle_edges=result.source_cycle_edges,
        candidate_cycle_edges=result.candidate_cycle_edges,
        source_bindings=result.source_bindings,
        candidate_bindings=result.candidate_bindings,
        terminal_source_ref=result.terminal_source_ref,
        cleanup_source_ref=result.cleanup_source_ref,
        terminal_carrier_ref=result.terminal_carrier_ref,
        terminal_route_refs=result.terminal_route_refs,
        terminal_subject_id=result.terminal_subject_id,
        terminal_subject_ref=result.terminal_subject_ref,
    )


def test_locator_tuples_are_normalized_and_duplicate_checked() -> None:
    model = import_authority_model()
    b0, b1 = block_ref("b0"), block_ref("b1")
    locator = model.RouteSubjectLocator(
        authority_id("p"), authority_id("g"), b0, 0x1000,
        [b1], [0x1100],
    )
    assert locator.destination_refs == (b1,)
    assert locator.destination_anchor_eas == (0x1100,)
    with pytest.raises(ValueError):
        model.RouteSubjectLocator(
            authority_id("p"), authority_id("g"), b0, 0x1000,
            [b1, b1], [0x1100, 0x1100],
        )


def test_parallel_locator_tuples_preserve_ref_to_anchor_associations() -> None:
    model = import_authority_model()
    b0, b1 = block_ref("b0"), block_ref("b1")
    route = model.RouteSubjectLocator(
        authority_id("p"), authority_id("g"), b0, 0x1000,
        [b1, b0], [0x1100, 0x1000],
    )
    assert route.destination_refs == (b0, b1)
    assert route.destination_anchor_eas == (0x1000, 0x1100)
    corridor = model.CorridorSubjectLocator(
        authority_id("c"), b0, 0x1000,
        [b1, b0], [0x1100, 0x1000],
    )
    assert corridor.member_refs == (b0, b1)
    assert corridor.member_anchor_eas == (0x1000, 0x1100)


def test_phase_binding_requires_serial_and_ea_together() -> None:
    model = import_authority_model()
    b0 = block_ref("b0")
    subject = model.SemanticSubjectRef(
        model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY,
        subject_id(model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY, model.BlockSubjectLocator(b0, 0x1000)), b0, 0x1000, model.BlockSubjectLocator(b0, 0x1000),
    )
    base = dict(subject=subject, phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
                block_ref=b0, graph_fingerprint=authority_id("g"), generation=0,
                status=model.SubjectBindingStatus.UNIQUE, serial=3, anchor_ea=0x1000,
                native_instruction_eas=(0x1000,), role=subject.role)
    model.PhaseSubjectBinding(**base)
    with pytest.raises(ValueError):
        model.PhaseSubjectBinding(**{**base, "serial": None})
    with pytest.raises(ValueError):
        model.PhaseSubjectBinding(**{**base, "anchor_ea": None})


def test_nonunique_phase_binding_has_no_serial_or_anchor() -> None:
    model = import_authority_model()
    b0 = block_ref("b0")
    subject = model.SemanticSubjectRef(
        model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY,
        subject_id(model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY, model.BlockSubjectLocator(b0, 0x1000)), b0, 0x1000, model.BlockSubjectLocator(b0, 0x1000),
    )
    with pytest.raises(ValueError):
        model.PhaseSubjectBinding(
            subject, model.UnflattenAuthorityPhase.PRODUCER_FORECAST, None,
            authority_id("g"), 0, model.SubjectBindingStatus.MISSING, 1, None,
            (), subject.role,
        )


def test_evidence_payload_union_is_closed() -> None:
    model = import_authority_model()
    binding = object()
    with pytest.raises((TypeError, ValueError)):
        _evidence_factory(model.AuthorityEvidence,
            model.AuthorityEvidenceKind.PHASE_BINDING,
            object(), model.UnflattenAuthorityPhase.PRODUCER_FORECAST, binding,
        )


def test_source_catalog_rejects_duplicate_refs() -> None:
    model = import_authority_model()
    witness = model.SourceBlockIdentityWitness(block_ref("b0"), 0x1000, (0x1000,))
    key = model.NativePreanalysisKey(
        "input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64,
    )
    with pytest.raises(ValueError):
        model.SourceIdentityCatalog(key, 0, (witness, witness))


def test_source_block_witness_anchor_must_be_one_of_native_origins() -> None:
    model = import_authority_model()
    with pytest.raises(ValueError, match="anchor_ea"):
        model.SourceBlockIdentityWitness(block_ref("b0"), 0x2000, (0x1000,))


def _candidate_prefix_correlation_fixture(model, *, include_second: bool = True):
    exclusion_id = authority_id("candidate-prefix-exclusion")
    proof_id = authority_id("candidate-prefix-proof")
    claim_id = authority_id("candidate-prefix-claim")
    forecast_id = authority_id("candidate-prefix-forecast")
    path_ids = (authority_id("candidate-prefix-path-a"), authority_id("candidate-prefix-path-b"))
    prefixes = (
        (model.CorridorCoveragePathNode(block_ref("b0"), 0x1000),
         model.CorridorCoveragePathNode(block_ref("b1"), 0x1100)),
        (model.CorridorCoveragePathNode(block_ref("b2"), 0x1200),
         model.CorridorCoveragePathNode(block_ref("b1"), 0x1100)),
    )
    common = dict(
        exclusion_id=exclusion_id,
        exclusion_digest=authority_id("candidate-prefix-exclusion-digest"),
        claim_id=claim_id,
        proof_id=proof_id,
        source_fingerprint=authority_id("candidate-prefix-source"),
        candidate_fingerprint=authority_id("candidate-prefix-candidate"),
        source_generation=3,
        candidate_generation=4,
        phase_result_id=authority_id("candidate-prefix-result"),
    )
    correlation_a = model.CorridorSemanticExclusionCorrelation(
        path_id=path_ids[0], ordered_prefix=prefixes[0], **common,
    )
    correlation_b = model.CorridorSemanticExclusionCorrelation(
        path_id=path_ids[1], ordered_prefix=prefixes[1], **common,
    )
    correlations = tuple(sorted((correlation_a, correlation_b), key=lambda item: (item.exclusion_id, item.path_id)))
    if not include_second:
        correlations = correlations[:1]
    path_ids = tuple(sorted(path_ids))
    result_id = canonical_authority_id((
        "unflatten.corridor-coverage-phase.v1", forecast_id,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        common["source_fingerprint"], common["candidate_fingerprint"],
        common["source_generation"], common["candidate_generation"],
        path_ids, (), (), True, (exclusion_id,), True, False,
        tuple(item.content_key for item in correlations),
    ))
    correlation_a = replace(correlation_a, phase_result_id=result_id)
    correlation_b = replace(correlation_b, phase_result_id=result_id)
    result = model.CorridorCoveragePhaseResult(
        result_id, forecast_id, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        common["source_fingerprint"], common["candidate_fingerprint"], 3, 4,
        path_ids, (), (), True, (exclusion_id,), True, False,
        tuple(replace(item, phase_result_id=result_id) for item in correlations),
    )
    return result, result.semantic_exclusion_correlations[0], (
        result.semantic_exclusion_correlations[1]
        if len(result.semantic_exclusion_correlations) > 1 else None
    )


def test_candidate_prefix_correlation_supports_two_paths_with_unique_pair_keys() -> None:
    model = import_authority_model()
    result, first, second = _candidate_prefix_correlation_fixture(model)
    assert len(result.semantic_exclusion_correlations) == 2
    assert first.exclusion_id == second.exclusion_id
    assert first.path_id != second.path_id
    assert first.content_key != second.content_key
    assert all(
        not hasattr(item, name)
        for item in (first, second)
        for name in (
            "effect_subject", "handler_subject", "terminal_subject",
            "use_def_witness", "route_subject",
        )
    )


def test_equivalent_route_claim_requires_one_proof_and_one_stable_route_subject() -> None:
    """Route authority must not fan out across proofs or route subjects."""

    model = import_authority_model()
    valid = _valid_proposal(model)
    claim = valid["claims"][0]
    proof_id = claim.route_proof_ids[0]

    with pytest.raises(ValueError, match="exactly one proof"):
        replace(
            claim,
            route_proof_ids=tuple(sorted((proof_id, authority_id("second-proof")))),
        )

    alternate_locator = replace(
        claim.retired_route_subject.locator,
        atomic_group_id=authority_id("other-route-group"),
    )
    alternate_retired = _subject_factory(
        model.SemanticSubjectRef,
        kind=claim.retired_route_subject.kind,
        role=claim.retired_route_subject.role,
        block_ref=claim.retired_route_subject.block_ref,
        anchor_ea=claim.retired_route_subject.anchor_ea,
        locator=alternate_locator,
    )
    with pytest.raises(ValueError, match="one stable route subject"):
        replace(claim, retired_route_subject=alternate_retired)


@pytest.mark.parametrize("mutation", [
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(a, replace(b, path_id=a.path_id))),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(b, a)),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(replace(a, exclusion_digest=authority_id("wrong")), b)),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(replace(a, claim_id=authority_id("wrong")), b)),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(replace(a, proof_id=authority_id("wrong")), b)),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(replace(a, phase_result_id=authority_id("wrong")), b)),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(replace(a, source_fingerprint=authority_id("wrong")), b)),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(replace(a, candidate_fingerprint=authority_id("wrong")), b)),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(replace(a, source_generation=99), b)),
    lambda model, result, a, b: replace(result, semantic_exclusion_correlations=(replace(a, candidate_generation=99), b)),
])
def test_candidate_prefix_correlation_rejects_identity_digest_order_and_phase_drift(mutation) -> None:
    model = import_authority_model()
    result, first, second = _candidate_prefix_correlation_fixture(model)
    with pytest.raises((TypeError, ValueError)):
        mutation(model, result, first, second)


def test_use_def_fragment_witness_rejects_ids_without_actionable_severance() -> None:
    model = import_authority_model()
    with pytest.raises(ValueError, match="violation"):
        model.UseDefFragmentWitness(
            authority_id("fragment-invalid"), state_identity(), (),
            authority_id("redirect"), True, True, 0,
            (authority_id("violation"),),
        )


def test_proposed_contract_revalidates_low_level_use_def_mutation() -> None:
    model = import_authority_model()
    valid = _valid_proposal(model)
    witness = valid["use_def_witness"]
    object.__setattr__(witness, "violation_ids", (authority_id("violation"),))
    with pytest.raises(ValueError, match="use-def"):
        model.ProposedUnflattenContract(**valid)


def test_plan_input_catalog_and_handler_rows_are_closed() -> None:
    model = import_authority_model()
    b0 = block_ref("b0")
    handler = model.AuthoritativeHandlerInput(b0, 0x1000, [3, 1])
    assert handler.normalized_states == (1, 3)
    with pytest.raises(ValueError):
        model.AuthoritativeHandlerInput(b0, 0x1000, [])
    catalog = model.UnflattenPlanInputCatalog(
        model.UnflattenPlanShape.EXACT_EFFECT_ONLY, b0, b0, (b0,),
        (handler,), state_identity(),
    )
    assert catalog.authoritative_handlers == (handler,)
    assert "plan_inputs" in model.ProposedUnflattenContract.__dataclass_fields__


def test_legacy_shadow_transport_has_exact_closed_schema() -> None:
    model = import_authority_model()
    from hashlib import sha256

    from d810.transforms.unflatten_authority.legacy_wire import encode_legacy_value

    payload = encode_legacy_value({"legacy": [1, 2]})
    entry = model.LegacyShadowEntry(
        "dispatcher_corridor_coverage", payload, sha256(payload).hexdigest()
    )
    envelope = model.LegacyUnflattenShadowEnvelope(
        1, "plan", "snapshot", 0, (entry,)
    )
    assert tuple(model.LegacyShadowEntry.__dataclass_fields__) == (
        "key", "canonical_payload", "payload_sha256"
    )
    assert envelope.entries == (entry,)
    assert getattr(model.LegacyShadowEntry, "__slots__")


def test_supplied_ids_are_structurally_validated_only() -> None:
    model = import_authority_model()
    b0 = block_ref("b0")
    with pytest.raises(ValueError):
        model.BlockSubjectLocator(b0, 0xFFFFFFFFFFFFFFFF)
    with pytest.raises(ValueError):
        model.SourceBlockIdentityWitness(b0, 0x1000, (0x1000, 0x1000))


def test_every_evidence_kind_accepts_only_its_exact_payload_class() -> None:
    model = import_authority_model()
    b0 = block_ref("b0")
    subject = _subject(
        model, model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY,
        model.BlockSubjectLocator(b0, 0x1000),
    )
    binding = model.PhaseSubjectBinding(
        subject, model.UnflattenAuthorityPhase.PRODUCER_FORECAST, b0,
        authority_id("graph"), 0, model.SubjectBindingStatus.UNIQUE, 1,
        0x1000, (0x1000,), subject.role,
    )
    payloads = {
        model.AuthorityEvidenceKind.PHASE_BINDING: model.PhaseBindingEvidencePayload(binding),
        model.AuthorityEvidenceKind.TOPOLOGY: model.TopologyEvidencePayload(
            subject.subject_id, (), (), True, authority_id("expected"), authority_id("candidate"),
        ),
        model.AuthorityEvidenceKind.STRUCTURAL_LINEAGE: model.StructuralLineageEvidencePayload(
            subject.subject_id, (subject.subject_id,), model.StructuralDisposition.PRESERVED, (), None,
        ),
        model.AuthorityEvidenceKind.SEMANTIC_ROUTE: model.SemanticRouteEvidencePayload(
            subject.subject_id, (authority_id("proof"),), authority_id("group"),
            subject.subject_id, (subject.subject_id,), True,
        ),
        model.AuthorityEvidenceKind.EFFECT_SITE: model.EffectSiteEvidencePayload(
            subject.subject_id, model.EffectSiteKind.STORE, 0x1004, 1, 4, None, None,
            model.ProviderConsensusMode.NOT_APPLICABLE, (), True,
        ),
        model.AuthorityEvidenceKind.REACHABILITY: model.ReachabilityEvidencePayload(
            subject.subject_id, subject.subject_id, True, (subject.subject_id,),
        ),
        model.AuthorityEvidenceKind.USE_DEF_AUDIT: model.UseDefAuditEvidencePayload(
            authority_id("fragment"), state_identity(), True, True, 0, (),
        ),
        model.AuthorityEvidenceKind.CORRIDOR_COVERAGE: model.CorridorCoverageEvidencePayload(
            subject.subject_id, authority_id("forecast"), authority_id("phase-result"),
            (authority_id("path"),), (), (), True, (),
        ),
        model.AuthorityEvidenceKind.TERMINAL_CYCLE: _terminal_cycle_evidence_payload(
            model, _terminal_cycle_phase_result(model),
        ),
        model.AuthorityEvidenceKind.PATCH_STEP: model.PatchStepEvidencePayload(
            authority_id("plan"), 0, "redirect", b0, authority_id("step"), 0x1004, 1, 4,
        ),
        model.AuthorityEvidenceKind.GENERIC_CFG_GATE: model.GenericCfgGateEvidencePayload(
            model.GenericCfgGateKind.ENTRY_REACHABILITY, True, (subject.subject_id,), "ok",
        ),
    }
    assert set(payloads) == set(model._PAYLOAD_BY_KIND)
    for kind, payload in payloads.items():
        evidence = _evidence_factory(model.AuthorityEvidence,
            kind, subject,
            model.UnflattenAuthorityPhase.PRODUCER_FORECAST, payload,
        )
        assert evidence.payload is payload
        with pytest.raises(ValueError):
            replace(evidence, evidence_id="sha256:" + "0" * 64)
        for other_kind, other_payload in payloads.items():
            if other_kind is not kind:
                with pytest.raises(TypeError):
                    _evidence_factory(model.AuthorityEvidence,
                        kind, subject,
                        model.UnflattenAuthorityPhase.PRODUCER_FORECAST, other_payload,
                    )


def test_claim_fields_use_the_closed_15_1_rows() -> None:
    model = import_authority_model()
    b0, b1 = block_ref("b0"), block_ref("b1")
    infra = _subject(model, model.SemanticSubjectKind.BLOCK,
                     model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                     model.BlockSubjectLocator(b0, 0x1000))
    infra2 = _subject(model, model.SemanticSubjectKind.BLOCK,
                      model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                      model.BlockSubjectLocator(b1, 0x1100))
    corridor = _subject(model, model.SemanticSubjectKind.CORRIDOR,
                        model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
                        model.CorridorSubjectLocator(authority_id("corridor"), b0, 0x1000,
                                                     (b0, b1), (0x1000, 0x1100)))
    route_locator = model.RouteSubjectLocator(authority_id("route"), authority_id("group"),
                                               b0, 0x1000, (b1,), (0x1100,))
    route = _subject(model, model.SemanticSubjectKind.ROUTE,
                     model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, route_locator)
    source = _subject(model, model.SemanticSubjectKind.BLOCK,
                      model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                      model.BlockSubjectLocator(b0, 0x1000))
    destination = _subject(model, model.SemanticSubjectKind.BLOCK,
                           model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
                           model.BlockSubjectLocator(b1, 0x1100))
    effect = _subject(model, model.SemanticSubjectKind.EFFECT,
                      model.SemanticSubjectRole.EFFECT_SITE,
                      model.EffectSubjectLocator(b0, 0x1000, 0x1004, model.EffectSiteKind.STORE))
    discarded = _subject(model, model.SemanticSubjectKind.EFFECT,
                         model.SemanticSubjectRole.EFFECT_SITE,
                         model.EffectSubjectLocator(b0, 0x1000, 0x1008, model.EffectSiteKind.STORE))
    predicate = source
    terminal = _subject(model, model.SemanticSubjectKind.TERMINAL,
                        model.SemanticSubjectRole.TERMINAL_SITE,
                        model.TerminalSubjectLocator(b1, 0x1100, model.TerminalKind.RETURN, 0x1104))
    claims = [
        _claim_factory(model.RetiredDispatcherInfrastructureClaim,
            model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
                infra, corridor, (infra, infra2), (_retirement_catalog(model, (b0, b1), (0x1000, 0x1100), 0).proofs[0].proof_id,), 0,
                _retirement_catalog(model, (b0, b1), (0x1000, 0x1100), 0),
        ),
        _claim_factory(model.EquivalentSemanticRouteClaim,
            model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
            route, route, source, (destination,), (authority_id("route"),),
            authority_id("group"), 0,
        ),
        _claim_factory(model.ExactInfeasibleEffectClaim,
            model.UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT,
                discarded, source, predicate, destination, discarded, 1, state_identity(), 4,
                0x1004, 0x1008, 0x1008, model.SemanticEdgeRole.DIRECT,
            (authority_id("exact-proof"),),
            model.ProviderConsensusWitness(model.ProviderConsensusMode.NOT_APPLICABLE, ()), 0,
        ),
        _claim_factory(model.TerminalCycleBreakClaim,
            model.UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
            corridor, infra, terminal, (authority_id("terminal-proof"),), 0,
        ),
    ]
    assert all(claim for claim in claims)
    for claim in claims:
        with pytest.raises(ValueError):
            replace(claim, claim_id="sha256:" + "0" * 64)
    bad_subject = source
    with pytest.raises(ValueError):
        _claim_factory(model.RetiredDispatcherInfrastructureClaim,
            model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
            bad_subject, corridor, (infra,), (_retirement_catalog(model, (b0, b1), (0x1000, 0x1100), 0).proofs[0].proof_id,), 0,
            _retirement_catalog(model, (b0, b1), (0x1000, 0x1100), 0),
        )
    with pytest.raises(ValueError):
        _claim_factory(model.EquivalentSemanticRouteClaim,
            model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
            route, route, destination, (destination,), (authority_id("route"),), authority_id("group"), 0,
        )
    with pytest.raises(ValueError):
        _claim_factory(model.ExactInfeasibleEffectClaim,
            model.UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT,
            effect, source, predicate, source, discarded, 1, state_identity(), 4,
            0x1004, 0x1008, 0x100C, model.SemanticEdgeRole.DIRECT,
            (authority_id("proof"),), model.ProviderConsensusWitness(model.ProviderConsensusMode.NOT_APPLICABLE, ()), 0,
        )
    with pytest.raises(ValueError):
        _claim_factory(model.TerminalCycleBreakClaim,
            model.UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
            corridor, source, terminal, (authority_id("proof"),), 0,
        )


def test_exact_claim_rejects_provider_consensus_and_ambiguous_route_proofs() -> None:
    from .test_bind import _exact_fixture

    model = import_authority_model()
    claim = _exact_fixture()[1].claims[0]
    with pytest.raises(ValueError, match="provider consensus"):
        _reissued_claim(
            claim,
            consensus=model.ProviderConsensusWitness(
                model.ProviderConsensusMode.SINGLE_PROVIDER,
                (authority_id("provider"),),
            ),
        )
    with pytest.raises(ValueError, match="exactly one route proof"):
        _reissued_claim(
            claim,
            route_proof_ids=(authority_id("proof-a"), authority_id("proof-b")),
        )


def test_retirement_and_route_claims_preserve_cross_field_membership() -> None:
    model = import_authority_model()
    b0, b1 = block_ref("b0"), block_ref("b1")
    infra = _subject(model, model.SemanticSubjectKind.BLOCK,
                     model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                     model.BlockSubjectLocator(b0, 0x1000))
    corridor = _subject(model, model.SemanticSubjectKind.CORRIDOR,
                        model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
                        model.CorridorSubjectLocator(authority_id("corridor-x"), b0, 0x1000,
                                                     (b0, b1), (0x1000, 0x1100)))
    with pytest.raises(ValueError):
        _claim_factory(model.RetiredDispatcherInfrastructureClaim,
            model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
            infra, corridor, (infra,), (_retirement_catalog(model, (b0, b1), (0x1000, 0x1100), 0).proofs[0].proof_id,), 0,
            _retirement_catalog(model, (b0, b1), (0x1000, 0x1100), 0),
        )

    retired_locator = model.RouteSubjectLocator(
        authority_id("retired-route"), authority_id("group-x"), b0, 0x1000,
        (b1,), (0x1100,),
    )
    replacement_locator = model.RouteSubjectLocator(
        authority_id("replacement-route"), authority_id("group-x"), b1, 0x1100,
        (b0,), (0x1000,),
    )
    retired = _subject(model, model.SemanticSubjectKind.ROUTE,
                       model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, retired_locator)
    replacement = _subject(model, model.SemanticSubjectKind.ROUTE,
                           model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE, replacement_locator)
    source = _subject(model, model.SemanticSubjectKind.BLOCK,
                      model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                      model.BlockSubjectLocator(b0, 0x1000))
    destination = _subject(model, model.SemanticSubjectKind.BLOCK,
                           model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
                           model.BlockSubjectLocator(b1, 0x1100))
    with pytest.raises(ValueError):
        _claim_factory(model.EquivalentSemanticRouteClaim,
            model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
            retired, replacement, source, (destination,),
            (authority_id("proof-route"),), authority_id("group-x"), 0,
        )

    mismatched_group_route = _subject(
        model, model.SemanticSubjectKind.ROUTE,
        model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        model.RouteSubjectLocator(
            authority_id("proof-route"), authority_id("other-group"),
            b0, 0x1000, (b1,), (0x1100,),
        ),
    )
    with pytest.raises(ValueError, match="atomic_group_id"):
        _claim_factory(model.EquivalentSemanticRouteClaim,
            model.UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
            mismatched_group_route, mismatched_group_route,
            source,
            (destination,),
            (authority_id("proof-route"),), authority_id("group-x"), 0,
        )


def test_proposal_is_valid_but_rejects_incoherent_authority_inputs() -> None:
    model = import_authority_model()
    valid = _valid_proposal(model)
    proposal = model.ProposedUnflattenContract(**valid)
    assert proposal.plan_inputs.shape is model.UnflattenPlanShape.PARTIAL_REWRITE

    foreign_key = _native_key(model, fingerprint="z")
    foreign_evidence, _ = _canonical_evidence(model, native_key=foreign_key)
    with pytest.raises(ValueError):
        model.ProposedUnflattenContract(**{**valid, "route_evidence": foreign_evidence})
    with pytest.raises(ValueError, match="atomic_group_id"):
        _reissued_claim(
            valid["claims"][0],
            route_proof_ids=(authority_id("missing-proof"),),
        )
    with pytest.raises(ValueError):
        b0, b1 = block_ref("b0"), block_ref("b1")
        cycle = _subject(model, model.SemanticSubjectKind.CORRIDOR,
                         model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
                         model.CorridorSubjectLocator(authority_id("shape-corridor"), b0, 0x1000,
                                                      (b0, b1), (0x1000, 0x1100)))
        cleanup = _subject(model, model.SemanticSubjectKind.BLOCK,
                           model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                           model.BlockSubjectLocator(b0, 0x1000))
        terminal = _subject(model, model.SemanticSubjectKind.TERMINAL,
                            model.SemanticSubjectRole.TERMINAL_SITE,
                            model.TerminalSubjectLocator(b1, 0x1100, model.TerminalKind.RETURN, 0x1104))
        model.ProposedUnflattenContract(**{
            **valid,
            "source_identity_catalog": model.SourceIdentityCatalog(
                valid["source_identity_catalog"].native_key, 7,
                valid["source_identity_catalog"].blocks,
            ),
        })
    with pytest.raises(ValueError):
        model.ProposedUnflattenContract(**{
            **valid,
            "use_def_witness": model.UseDefFragmentWitness(
                authority_id("fragment-foreign"), StorageIdentity(StorageIdentityKind.REGISTER, 1),
                (block_ref("foreign"),), authority_id("redirect"), True, True, 0, (),
            ),
        })
    with pytest.raises(ValueError):
        model.ProposedUnflattenContract(**{
            **valid,
            "claims": (_reissued_claim(valid["claims"][0], source_generation=99),),
        })
    with pytest.raises(ValueError):
        model.ProposedUnflattenContract(**{
            **valid,
            "claims": (
                _claim_factory(model.TerminalCycleBreakClaim,
                        model.UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
                        cycle, cleanup, terminal, (authority_id("shape-proof"),), 3,
                ),
            ),
            "plan_inputs": model.UnflattenPlanInputCatalog(
                model.UnflattenPlanShape.EXACT_EFFECT_ONLY,
                block_ref("b0"), block_ref("b0"), (block_ref("b0"),),
                (model.AuthoritativeHandlerInput(block_ref("b0"), 0x1000, (1,)),),
                state_identity(),
            ),
        })


def test_terminal_cycle_only_partial_rewrite_proposal_is_valid() -> None:
    from .test_bind import _terminal_cycle_fixture

    model = import_authority_model()
    proposal, claim = _terminal_cycle_fixture()
    terminal_only = replace(proposal, claims=(claim,))
    assert terminal_only.plan_inputs.shape is model.UnflattenPlanShape.PARTIAL_REWRITE


def test_derived_inputs_require_one_phase_result_per_terminal_claim() -> None:
    from .test_bind import _terminal_cycle_fixture
    from .test_evaluate import _complete_inputs

    proposal, _claim = _terminal_cycle_fixture()
    with pytest.raises(ValueError, match="exactly one terminal-cycle phase result"):
        _complete_inputs(source_subjects=(), proposal=proposal)


def test_closed_unions_reject_local_alias_and_subclass_smuggling() -> None:
    model = import_authority_model()
    valid = _valid_proposal(model)
    b0 = block_ref("b0")
    owner = _subject(model, model.SemanticSubjectKind.BLOCK,
                     model.SemanticSubjectRole.EFFECT_SITE,
                     model.BlockSubjectLocator(b0, 0x1000))
    alias = _claim_factory(model.LocalAliasEffectScalarizationClaim,
        model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        _subject(model, model.SemanticSubjectKind.BLOCK,
                 model.SemanticSubjectRole.EFFECT_SITE,
                 model.BlockSubjectLocator(owner.block_ref, 0x1000)),
        0, 0x1000, 1, "alias", "base", None, None, authority_id("step"), 3,
    )
    with pytest.raises(ValueError):
        replace(alias, claim_id="sha256:" + "0" * 64)
    with pytest.raises(TypeError):
        model.ProposedUnflattenContract(**{**valid, "claims": (alias,)})

    class RefSubclass(model.LogicalBlockRef):
        pass

    with pytest.raises(TypeError):
        model.BlockSubjectLocator(RefSubclass("authority-test", "x", 1), 0x1000)

    class HandlerSubclass(model.AuthoritativeHandlerInput):
        pass

    with pytest.raises(TypeError):
        model.UnflattenPlanInputCatalog(
            model.UnflattenPlanShape.PARTIAL_REWRITE, block_ref("b0"), block_ref("b0"),
            (block_ref("b0"),),
            (HandlerSubclass(block_ref("b0"), 0x1000, (1,)),), state_identity(),
        )

    class CatalogSubclass(model.SourceIdentityCatalog):
        pass

    with pytest.raises(TypeError):
        model.ProposedUnflattenContract(**{
            **valid,
            "source_identity_catalog": CatalogSubclass(
                valid["source_identity_catalog"].native_key,
                valid["source_identity_catalog"].generation,
                valid["source_identity_catalog"].blocks,
            ),
        })


def test_source_and_handler_catalogs_reject_cross_row_duplicates() -> None:
    model = import_authority_model()
    key = _native_key(model)
    b0, b1 = block_ref("b0"), block_ref("b1")
    with pytest.raises(ValueError):
        model.SourceIdentityCatalog(
            key, 0,
            (
                model.SourceBlockIdentityWitness(b0, 0x1000, (0x1000,)),
                model.SourceBlockIdentityWitness(b1, 0x1100, (0x1000,)),
            ),
        )
    with pytest.raises(ValueError):
        model.UnflattenPlanInputCatalog(
            model.UnflattenPlanShape.PARTIAL_REWRITE, b0, b0, (b0,),
            (
                model.AuthoritativeHandlerInput(b1, 0x1100, (1,)),
                model.AuthoritativeHandlerInput(b1, 0x1100, (2,)),
            ), state_identity(),
        )


def test_catalog_binds_exact_anchors_and_native_keys() -> None:
    model = import_authority_model()
    valid = _valid_proposal(model)
    blocks = list(valid["source_identity_catalog"].blocks)
    with pytest.raises(ValueError):
        model.SourceBlockIdentityWitness(blocks[0].block_ref, 0x9999, (0x1000,))

    foreign_key = _native_key(model, fingerprint="foreign-native")
    foreign_identity = StableBlockIdentity.from_instruction_eas(
        [0x2000], native_key=foreign_key,
    )
    with pytest.raises(ValueError):
        model.SourceIdentityCatalog(
            valid["source_identity_catalog"].native_key, 3,
            (model.SourceBlockIdentityWitness(
                model.NativeBlockRef(foreign_identity), 0x2000, (0x2000,)
            ),),
        )


def test_alias_host_text_sha1_is_lowercase_16_hex() -> None:
    model = import_authority_model()
    b0 = block_ref("b0")
    owner = _subject(model, model.SemanticSubjectKind.BLOCK,
                     model.SemanticSubjectRole.EFFECT_SITE,
                     model.BlockSubjectLocator(b0, 0x1000))
    kwargs = dict(
        claim_id=authority_id("alias-sha"),
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=owner, step_index=0, host_ea=0x1000, host_opcode=1,
        alias_token="alias", base_token="base", host_text_sha1="a" * 16,
        value_size=None, step_digest=authority_id("step-sha"), source_generation=0,
    )
    _claim_factory(model.LocalAliasEffectScalarizationClaim, **{key: value for key, value in kwargs.items() if key != "claim_id"})
    with pytest.raises(ValueError):
        _claim_factory(model.LocalAliasEffectScalarizationClaim, **{
            **{key: value for key, value in kwargs.items() if key != "claim_id"},
            "owner_subject": _subject(
                model, model.SemanticSubjectKind.BLOCK,
                model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
                model.BlockSubjectLocator(b0, 0x1000),
            )})
    for malformed in ("A" * 16, "a" * 15, "a" * 17, "z" * 16):
        with pytest.raises(ValueError):
            _claim_factory(model.LocalAliasEffectScalarizationClaim, **{
                **{key: value for key, value in kwargs.items() if key != "claim_id"},
                "host_text_sha1": malformed,
            })


def test_unordered_model_collections_have_reversed_input_equality() -> None:
    model = import_authority_model()
    key = _native_key(model)
    b0, b1 = block_ref("b0"), block_ref("b1")
    blocks = (
        model.SourceBlockIdentityWitness(b0, 0x1000, (0x1000,)),
        model.SourceBlockIdentityWitness(b1, 0x1100, (0x1100,)),
    )
    assert model.SourceIdentityCatalog(key, 0, blocks) == model.SourceIdentityCatalog(key, 0, blocks[::-1])
    handlers = (
        model.AuthoritativeHandlerInput(b0, 0x1000, (1,)),
        model.AuthoritativeHandlerInput(b1, 0x1100, (2,)),
    )
    first = model.UnflattenPlanInputCatalog(
        model.UnflattenPlanShape.PARTIAL_REWRITE, b0, b0, (b0, b1), handlers, state_identity(),
    )
    second = model.UnflattenPlanInputCatalog(
        model.UnflattenPlanShape.PARTIAL_REWRITE, b0, b0, (b1, b0), handlers[::-1], state_identity(),
    )
    assert first == second
    assert model.ProviderConsensusWitness(
        model.ProviderConsensusMode.MULTI_PROVIDER_CONSENSUS,
        (authority_id("p1"), authority_id("p2")),
    ) == model.ProviderConsensusWitness(
        model.ProviderConsensusMode.MULTI_PROVIDER_CONSENSUS,
        (authority_id("p2"), authority_id("p1")),
    )


def test_plan_shape_uses_complete_dispatcher_inventory_and_retired_members() -> None:
    model = import_authority_model()
    valid = _valid_proposal(model)
    valid_base = model.ProposedUnflattenContract(**valid)
    valid["corridor_coverage_forecast"] = _minimal_corridor_forecast(model, valid_base)
    b0, b1, b2 = block_ref("b0"), block_ref("b1"), block_ref("b2")
    infra = _subject(model, model.SemanticSubjectKind.BLOCK,
                     model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                     model.BlockSubjectLocator(b0, 0x1000))
    infra2 = _subject(model, model.SemanticSubjectKind.BLOCK,
                      model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                      model.BlockSubjectLocator(b1, 0x1300))
    corridor = _subject(model, model.SemanticSubjectKind.CORRIDOR,
                        model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
                        model.CorridorSubjectLocator(authority_id("full-corridor"), b0, 0x1000,
                                                     (b0, b1), (0x1000, 0x1300)))
    retirement_catalog = _retirement_catalog(model, (b0, b1), (0x1000, 0x1300), 3)
    retirement = _claim_factory(model.RetiredDispatcherInfrastructureClaim,
        model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
            infra, corridor, (infra, infra2), (retirement_catalog.proofs[0].proof_id,), 3,
            retirement_catalog,
    )
    assert model.AuthoritativeHandlerInput(b2, 0x1100, (1,)).block_ref not in {
        member.locator.block_ref for member in retirement.member_subjects
    }
    full_inputs = model.UnflattenPlanInputCatalog(
        model.UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT,
        b0, b0, (b0, b1),
        (model.AuthoritativeHandlerInput(b2, 0x1100, (1,)),), state_identity(),
    )
    assert model.ProposedUnflattenContract(
            **{**valid, "claims": (retirement,), "plan_inputs": full_inputs,
               "retirement_catalog": retirement_catalog}
    )
    partial_inputs = model.UnflattenPlanInputCatalog(
        model.UnflattenPlanShape.PARTIAL_REWRITE,
        b0, b0, (b0, b1),
        (model.AuthoritativeHandlerInput(b2, 0x1100, (1,)),), state_identity(),
    )
    with pytest.raises(ValueError):
        model.ProposedUnflattenContract(
            **{**valid, "claims": (retirement,), "plan_inputs": partial_inputs}
        )

    foreign_infra = _subject(model, model.SemanticSubjectKind.BLOCK,
                             model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                             model.BlockSubjectLocator(b2, 0x1100))
    foreign_corridor = _subject(model, model.SemanticSubjectKind.CORRIDOR,
                                model.SemanticSubjectRole.DISPATCHER_CORRIDOR,
                                model.CorridorSubjectLocator(
                                    authority_id("foreign-corridor"), b2, 0x1100,
                                    (b2,), (0x1100,),
                                ))
    foreign_retirement = _claim_factory(model.RetiredDispatcherInfrastructureClaim,
        model.UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        foreign_infra, foreign_corridor, (foreign_infra,),
        (_retirement_catalog(model, (b2,), (0x1100,), 3).proofs[0].proof_id,), 3,
        _retirement_catalog(model, (b2,), (0x1100,), 3),
    )
    with pytest.raises(ValueError, match="retirement claims must share|dispatcher_member_refs"):
        model.ProposedUnflattenContract(
            **{**valid, "claims": (foreign_retirement,), "plan_inputs": partial_inputs}
        )
