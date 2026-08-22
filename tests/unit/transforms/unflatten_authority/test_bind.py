"""Exact source/projected binding contracts for Task 9."""

from __future__ import annotations

import pytest

from d810.transforms.unflatten_authority import bind
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id, _claim_factory, _subject_factory
from .helpers import block_ref
from .test_model import _valid_proposal


def _fixture():
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    catalog = proposal.source_identity_catalog
    return proposal, catalog


def _exact_fixture(*, optional_owner: bool = False):
    """Build the producer-owned four-block state-choice receipt fixture."""
    from d810.analyses.control_flow.effect_branch_exclusion import build_exact_state_branch_effect_exclusion
    from d810.analyses.control_flow.semantic_route_evidence import (
        CanonicalSemanticEvidence, SemanticCarrierProof, SemanticCorridorPoint,
        SemanticPredicateKind, SemanticPredicateProof, SemanticRouteDestination,
        SemanticRouteProof, SemanticRouteProofKind, SemanticRouteShape,
        SemanticStateWriteDeliveryKind, SemanticStateWriteProof,
    )
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import StableBlockIdentity
    from d810.ir.flowgraph import (
        BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot,
        MopSnapshot, OperandKind, PredicateKind,
    )
    from d810.ir.expressions import ValueOpKind
    from d810.ir.semantic_edge import SemanticEdgeRole
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.cfg_transaction import NativeBlockRef
    from d810.transforms.unflatten_authority import producer_api
    from d810.transforms.unflatten_authority.model import UseDefFragmentWitness

    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    state = StorageIdentity(StorageIdentityKind.STACK, 4)
    state_number = MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7)
    state_stack = MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,))
    specs = (
        (0, (1,), (), 0x1000, (InsnSnapshot(0, 0x1000, (), l=state_number, d=state_stack, kind=InsnKind.MOV, value_op_kind=ValueOpKind.MOVE), InsnSnapshot(0, 0x1001, (), l=MopSnapshot(kind=OperandKind.BLOCK, block_ref=1), kind=InsnKind.GOTO))),
        (1, (2, 3), (0,), 0x2000, (InsnSnapshot(0, 0x2000, (), kind=InsnKind.NOP, value_op_kind=ValueOpKind.VENDOR), InsnSnapshot(0, 0x2001, (), l=state_stack, r=state_number, d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2), kind=InsnKind.COND_JUMP, branch_predicate=PredicateKind.EQ, is_conditional_jump=True),)),
        (2, (), (1,), 0x3000, (InsnSnapshot(0, 0x3000, (), kind=InsnKind.NOP),)),
        (3, (), (1,), 0x4000, (InsnSnapshot(0, 0x4000, (), kind=InsnKind.CALL, is_call=True),)),
        (4, (), (), 0x5000, (InsnSnapshot(0, 0x5000, (), kind=InsnKind.NOP),)),
    )
    source = FlowGraph({serial: BlockSnapshot(serial, 0, succs, preds, 0, ea, insns,
        kind=BlockKind.TWO_WAY if len(succs) == 2 else BlockKind.ONE_WAY if succs else BlockKind.ZERO_WAY)
        for serial, succs, preds, ea, insns in specs}, 0, 0x5000)
    refs = {serial: NativeBlockRef(StableBlockIdentity.from_instruction_eas(
        [ins.ea for ins in insns], native_key=key)) for serial, _s, _p, _ea, insns in specs}
    producer_api.build_source_identity_catalog(source, refs, native_key=key, source_generation=1)
    source_point = SemanticCorridorPoint(refs[0].identity, 0x1000)
    predicate_point = SemanticCorridorPoint(refs[1].identity, 0x2001)
    predicate_consumer = SemanticCorridorPoint(refs[1].identity, 0x2000)
    state_write = SemanticStateWriteProof(refs[0].identity, 0x1000, state, 4, 7, (0x1000, 0x2000), None, (), SemanticStateWriteDeliveryKind.CONDITIONAL)
    predicate = SemanticPredicateProof(SemanticPredicateKind.STORAGE_EQUALS, predicate_point, predicate_consumer, (predicate_point, predicate_consumer), state, 4, 8, None, ())
    carrier = SemanticCarrierProof(authority_id("carrier"), source_point, (predicate_consumer,), (source_point, predicate_consumer), state, 4, (7, 8), (0x1000,))
    route = SemanticRouteProof(authority_id("route"), authority_id("group"), SemanticRouteProofKind.STATE_CHOICE, SemanticRouteShape.CONDITIONAL, refs[1].identity, 0x2000, (
        SemanticRouteDestination(SemanticEdgeRole.CONDITIONAL_TAKEN, 7, refs[2].identity, 0x3000),
        SemanticRouteDestination(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH, 8, refs[3].identity, 0x4000),), source_owner_identity=None if optional_owner else refs[0].identity, source_owner_anchor_ea=None if optional_owner else 0x1000, state_write=state_write, predicate=predicate, carriers=(carrier,), diagnostic_provenance=(("provider_proof_kind", "state_choice"),))
    evidence = CanonicalSemanticEvidence(key, 1, authority_id("group"), (route,))
    exclusion = build_exact_state_branch_effect_exclusion(
        source, source, normalized_state=7, source_serial=0,
        predicate_serial=1, selected_target_serial=2,
        discarded_effect_serial=3, state_identity=state,
    )
    assert exclusion is not None
    witness = UseDefFragmentWitness(authority_id("fragment"), state, (refs[0],), authority_id("redirect"), True, True, 0, ())
    proposal = producer_api.build_proposal(plan_id=authority_id("plan"), source=source, block_refs_by_serial=refs, source_generation=1, canonical_route_evidence=evidence, exact_state_effect_exclusions=(exclusion,), dispatcher_entry_serial=1, dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,), state_identity=state, use_def_witness=witness)
    return source, proposal, exclusion, refs


def test_bind_subjects_requires_exact_catalog_identity_and_generation() -> None:
    proposal, catalog = _fixture()
    subjects = (
        proposal.plan_inputs.authoritative_handlers[0],
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=subjects[0].block_ref,
        anchor_ea=subjects[0].anchor_ea,
        locator=model.HandlerSubjectLocator(
            subjects[0].block_ref, subjects[0].anchor_ea, subjects[0].normalized_states,
        ),
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    bound = bind.bind_subjects(
        (subject,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        graph_fingerprint=authority_id("source"), generation=catalog.generation,
        serial_by_ref=serials,
    )
    assert bound[0].status is model.SubjectBindingStatus.UNIQUE
    assert bound[0].serial == serials[subject.block_ref]

    with pytest.raises(ValueError, match="generation"):
        bind.bind_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            graph_fingerprint=authority_id("source"), generation=catalog.generation + 1,
            serial_by_ref=serials,
        )


def test_bind_subjects_rejects_near_match_anchor_and_foreign_serial_rows() -> None:
    proposal, catalog = _fixture()
    handler = proposal.plan_inputs.authoritative_handlers[0]
    locator = model.HandlerSubjectLocator(
        handler.block_ref, handler.anchor_ea, handler.normalized_states,
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=handler.block_ref,
        anchor_ea=handler.anchor_ea,
        locator=locator,
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    with pytest.raises(ValueError, match="serial binding"):
        bind.bind_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("candidate"), generation=catalog.generation,
            serial_by_ref={**serials, block_ref("foreign"): 99},
        )
    near_locator = model.HandlerSubjectLocator(
        handler.block_ref, handler.anchor_ea + 1, handler.normalized_states,
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.HANDLER,
        role=model.SemanticSubjectRole.AUTHORITATIVE_HANDLER,
        block_ref=handler.block_ref,
        anchor_ea=handler.anchor_ea + 1,
        locator=near_locator,
    )
    with pytest.raises(ValueError, match="near-match"):
        bind.bind_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("candidate"), generation=catalog.generation,
            serial_by_ref=serials,
        )


def test_source_effect_is_unique_but_projected_effect_is_exactly_missing() -> None:
    _proposal, catalog = _fixture()
    b1 = next(item.block_ref for item in catalog.blocks if item.anchor_ea == 0x1300)
    effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=b1,
        anchor_ea=0x1300,
        locator=model.EffectSubjectLocator(
            b1, 0x1300, 0x1300, model.EffectSiteKind.STORE,
        ),
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    source = bind.bind_source_subjects(
        (effect,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        graph_fingerprint=authority_id("source"), generation=catalog.generation,
        serial_by_ref=serials,
    )
    projected = bind.bind_projected_subjects(
        (effect,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("candidate"), generation=catalog.generation,
        serial_by_ref={ref: serial for ref, serial in serials.items() if ref != b1},
    )
    assert source[0].status is model.SubjectBindingStatus.UNIQUE
    assert source[0].serial == serials[b1]
    assert projected[0].status is model.SubjectBindingStatus.MISSING
    assert projected[0].serial is None

    with pytest.raises(ValueError, match="native-origin binding"):
        bind.bind_subjects(
            (effect,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            graph_fingerprint=authority_id("source"), generation=catalog.generation,
            serial_by_ref=serials,
            native_instruction_eas_by_ref={},
        )
    with pytest.raises(ValueError, match="every projected reference"):
        bind.bind_projected_subjects(
            (effect,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("candidate"), generation=catalog.generation,
            serial_by_ref={ref: serial for ref, serial in serials.items() if ref != b1},
            native_instruction_eas_by_ref={},
        )


def test_exact_effect_facade_replays_source_and_projected_receipt() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source,
        source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref,
        exclusion=exclusion, claim=claim, proposal=proposal,
        generation=1,
    )
    assert all(item.status is model.SubjectBindingStatus.UNIQUE for item in result.source_bindings)
    assert all(item.status is model.SubjectBindingStatus.UNIQUE for item in result.projected_bindings)
    assert result.claim_id == claim.claim_id
    from d810.transforms.unflatten_authority.ids import semantic_graph_fingerprint
    assert result.source_graph_fingerprint == semantic_graph_fingerprint(source)
    assert result.projected_graph_fingerprint == semantic_graph_fingerprint(source)
    assert result.generation == proposal.source_identity_catalog.generation


def test_exact_effect_facade_accepts_optional_absent_route_owner() -> None:
    source, proposal, exclusion, refs = _exact_fixture(optional_owner=True)
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    assert result.claim == claim


def test_exact_effect_facade_allows_unrelated_projected_catalog_omission() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    projected = source.__class__(
        {serial: block for serial, block in source.blocks.items() if serial != 4},
        source.entry_serial,
        source.func_ea,
    )
    serial_by_ref = {ref: serial for serial, ref in refs.items() if serial != 4}
    result = bind.bind_exact_effect_claim(
        source=source,
        projected=projected,
        source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref,
        exclusion=exclusion,
        claim=claim,
        proposal=proposal,
        generation=1,
    )
    claim_refs = {
        subject.block_ref
        for subject in (
            claim.source_subject,
            claim.predicate_subject,
            claim.selected_target_subject,
            claim.discarded_effect_subject,
        )
    }
    assert {ref for ref, _serial in result.source_serial_rows} == claim_refs
    assert {ref for ref, _serial in result.projected_serial_rows} == claim_refs
    assert all(item.status is model.SubjectBindingStatus.UNIQUE for item in result.projected_bindings)


def test_exact_effect_facade_rejects_topology_ingress_and_claim_near_matches() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    kwargs = dict(source=source, projected=source, source_block_refs_by_serial=refs,
                  projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
                  claim=claim, proposal=proposal, generation=1)
    from dataclasses import replace
    with pytest.raises(ValueError, match="canonical producer|claim"):
        bind.bind_exact_effect_claim(**{**kwargs, "claim": replace(claim, width=8)})
    with pytest.raises(ValueError, match="projected block identity"):
        bind.bind_exact_effect_claim(**{**kwargs, "projected_serial_by_ref": {
            **serial_by_ref, next(iter(serial_by_ref)): 99,
        }})
    with pytest.raises(ValueError, match="topology"):
        bind.bind_exact_effect_claim(**{**kwargs, "exclusion": replace(
            exclusion, selected_target_serial=exclusion.discarded_effect_serial,
        )})
    with pytest.raises(TypeError):
        bind.bind_exact_effect_claim(**kwargs, source_graph_fingerprint="sha256:" + "0" * 64)


def test_exact_effect_facade_rejects_graph_mutation_and_noncanonical_ref_rows() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    kwargs = dict(source=source, projected=source, source_block_refs_by_serial=refs,
                  projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
                  claim=claim, proposal=proposal, generation=1)
    from dataclasses import replace
    mutated = replace(
        source,
        blocks={
            **source.blocks,
            exclusion.discarded_effect_serial: replace(
                source.blocks[exclusion.discarded_effect_serial],
                native_start_ea=0x4001,
            ),
        },
    )
    with pytest.raises(ValueError):
        bind.bind_exact_effect_claim(**{**kwargs, "projected": mutated})
    with pytest.raises(ValueError, match="non-canonical row"):
        bind.bind_exact_effect_claim(**{**kwargs, "source_block_refs_by_serial": {
            **refs, 0.9: refs[0],
        }})
    with pytest.raises(ValueError, match="non-canonical row"):
        bind.bind_exact_effect_claim(**{**kwargs, "projected_serial_by_ref": {
            ref: (0.0 if serial == 0 else serial)
            for ref, serial in serial_by_ref.items()
        }})


def test_exact_effect_binding_result_constructor_rejects_half_bound_records() -> None:
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult()
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            model.ExactInfeasibleEffectClaim, None, None, None, (), (), (), (),
            authority_id("source"), authority_id("projected"), 1,
        )


def test_exact_effect_binding_registry_does_not_retain_results() -> None:
    import gc
    import weakref

    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    registry = next(
        cell.cell_contents
        for cell in bind.validate_exact_effect_binding_result.__closure__ or ()
        if type(cell.cell_contents) is dict
    )
    before = len(registry)
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    assert len(registry) == before + 1
    reference = weakref.ref(result)
    del result
    gc.collect()
    assert reference() is None
    assert len(registry) == before


def test_exact_effect_binding_result_revalidates_mutated_bindings_and_digests() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    original_fingerprint = result.source_graph_fingerprint
    object.__setattr__(result, "source_graph_fingerprint", "sha256:x")
    with pytest.raises(ValueError, match="content seal"):
        bind.validate_exact_effect_binding_result(result)
    object.__setattr__(result, "source_graph_fingerprint", original_fingerprint)
    bind.validate_exact_effect_binding_result(result)
    original_seal = result._content_seal
    object.__setattr__(result, "_content_seal", "sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="content seal"):
        bind.validate_exact_effect_binding_result(result)
    object.__setattr__(result, "_content_seal", original_seal)
    bind.validate_exact_effect_binding_result(result)
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            "sha256:x", result.projected_graph_fingerprint, result.generation,
        )
    mutated = result.source_bindings[0]
    object.__setattr__(mutated, "serial", True)
    with pytest.raises((TypeError, ValueError)):
        bind.validate_exact_effect_binding_result(result)
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )
    object.__setattr__(mutated, "serial", next(
        serial for ref, serial in result.source_serial_rows
        if ref == mutated.block_ref
    ))

    rows = list(result.source_serial_rows)
    rows[0] = (rows[0][0], rows[0][1] + 99)
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            tuple(rows), result.projected_serial_rows, result.source_bindings,
            result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )

    reissued_claim = _claim_factory(
        model.ExactInfeasibleEffectClaim,
        **{
            field: getattr(result.claim, field)
            for field in (
                "kind", "effect_subject", "source_subject", "predicate_subject",
                "selected_target_subject", "discarded_effect_subject", "normalized_state",
                "state_identity", "width", "source_write_ea", "predicate_branch_ea",
                "discarded_effect_ea", "selected_edge_role", "route_proof_ids",
                "consensus",
            )
        },
        source_generation=99,
    )
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            reissued_claim, result.proposal, result.exclusion, result.source_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )


def test_exact_effect_binding_result_rejects_noncanonical_row_and_binding_order() -> None:
    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            tuple(reversed(result.source_serial_rows)), result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )


def test_exact_effect_binding_result_rejects_canonical_reissued_claim_relationships() -> None:
    from dataclasses import replace

    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    fields = (
        "kind", "effect_subject", "source_subject", "predicate_subject",
        "selected_target_subject", "discarded_effect_subject", "normalized_state",
        "state_identity", "width", "source_write_ea", "predicate_branch_ea",
        "discarded_effect_ea", "selected_edge_role", "route_proof_ids", "consensus",
    )
    base = {field: getattr(claim, field) for field in fields}
    for name, value in (
        ("normalized_state", claim.normalized_state + 1),
        ("source_write_ea", claim.source_write_ea + 1),
        (
            "selected_edge_role",
            next(
                destination.role
                for destination in proposal.route_evidence.route_proofs[0].destinations
                if destination.role is not claim.selected_edge_role
            ),
        ),
    ):
        forged = _claim_factory(
            model.ExactInfeasibleEffectClaim,
            **{**base, name: value, "source_generation": claim.source_generation},
        )
        with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
            bind.ExactEffectBindingResult(
                forged, result.proposal, result.exclusion, result.source_catalog,
                result.source_serial_rows, result.projected_serial_rows,
                result.source_bindings, result.projected_bindings,
                result.source_graph_fingerprint, result.projected_graph_fingerprint,
                result.generation,
            )
        forged_proposal = replace(result.proposal, claims=(forged,))
        with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
            bind.ExactEffectBindingResult(
                forged, forged_proposal, result.exclusion, result.source_catalog,
                result.source_serial_rows, result.projected_serial_rows,
                result.source_bindings, result.projected_bindings,
                result.source_graph_fingerprint, result.projected_graph_fingerprint,
                result.generation,
            )
        with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
            bind.ExactEffectBindingResult(
                result.claim, result.proposal, result.exclusion, result.source_catalog,
                result.source_serial_rows, result.projected_serial_rows,
                tuple(reversed(result.source_bindings)), result.projected_bindings,
                result.source_graph_fingerprint, result.projected_graph_fingerprint,
                result.generation,
            )


def test_exact_effect_binding_rejects_canonical_rebuilt_wrong_anchor_and_origins() -> None:
    from dataclasses import replace

    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    result = bind.bind_exact_effect_claim(
        source=source, projected=source, source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref, exclusion=exclusion,
        claim=claim, proposal=proposal, generation=1,
    )
    binding = result.source_bindings[0]
    with pytest.raises(ValueError, match="anchor"):
        replace(binding, serial=999, anchor_ea=0xDEAD, native_instruction_eas=(0xDEAD,))
    object.__setattr__(binding, "anchor_ea", 0xBEEF)
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            result.claim, result.proposal, result.exclusion, result.source_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings,
            result.projected_bindings, result.source_graph_fingerprint,
            result.projected_graph_fingerprint, result.generation,
        )


def test_exact_semantic_correlation_is_not_public_authority() -> None:
    from d810.transforms.unflatten_authority import producer_api

    assert "_ExactEffectSemanticCorrelation" not in producer_api.__all__
    assert "_resolve_exact_effect_semantics" not in producer_api.__all__
    assert "validate_exact_effect_correlation" not in producer_api.__all__
    assert not hasattr(producer_api, "ExactEffectSemanticCorrelation")
    assert not hasattr(producer_api, "resolve_exact_effect_semantics")
    assert not hasattr(producer_api, "validate_exact_effect_correlation")
    assert not hasattr(bind, "_BindingConstructionToken")
    assert not hasattr(bind, "_mint_exact_effect_binding_result")


def test_exact_effect_public_binding_rejects_coordinated_kind_and_ea_forgery() -> None:
    from dataclasses import replace
    from d810.analyses.control_flow.effect_branch_exclusion import build_exact_state_branch_effect_exclusion
    from d810.ir.flowgraph import InsnKind
    from d810.transforms.unflatten_authority import producer_api

    source, proposal, exclusion, refs = _exact_fixture()
    claim = proposal.claims[0]
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    kwargs = dict(
        source=source,
        projected=source,
        source_block_refs_by_serial=refs,
        projected_serial_by_ref=serial_by_ref,
        exclusion=exclusion,
        claim=claim,
        proposal=proposal,
        generation=1,
    )
    result = bind.bind_exact_effect_claim(**kwargs)
    call_block = source.blocks[exclusion.discarded_effect_serial]
    store = replace(call_block.insn_snapshots[0], kind=InsnKind.STORE, is_call=False)
    kind_forged = replace(
        source,
        blocks={
            **source.blocks,
            call_block.serial: replace(call_block, insn_snapshots=(store,)),
        },
    )
    with pytest.raises(ValueError):
        bind.bind_exact_effect_claim(**{**kwargs, "source": kind_forged, "projected": kind_forged})

    forged_exclusion = build_exact_state_branch_effect_exclusion(
        kind_forged, kind_forged, normalized_state=7, source_serial=0,
        predicate_serial=1, selected_target_serial=2,
        discarded_effect_serial=3, state_identity=proposal.plan_inputs.state_identity,
    )
    assert forged_exclusion is not None
    forged_proposal = producer_api.build_proposal(
        plan_id=proposal.plan_id, source=kind_forged, block_refs_by_serial=refs,
        source_generation=1, canonical_route_evidence=proposal.route_evidence,
        exact_state_effect_exclusions=(forged_exclusion,), dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=proposal.use_def_witness,
    )
    with pytest.raises(TypeError, match="minted by bind_exact_effect_claim"):
        bind.ExactEffectBindingResult(
            forged_proposal.claims[0], forged_proposal, forged_exclusion,
            forged_proposal.source_identity_catalog,
            result.source_serial_rows, result.projected_serial_rows,
            result.source_bindings, result.projected_bindings,
            result.source_graph_fingerprint, result.projected_graph_fingerprint,
            result.generation,
        )

    shifted = replace(call_block.insn_snapshots[0], native_ea=0x4001, ea=0x4001)
    ea_forged = replace(
        source,
        blocks={
            **source.blocks,
            call_block.serial: replace(call_block, native_start_ea=0x4001, insn_snapshots=(shifted,)),
        },
    )
    with pytest.raises(ValueError):
        bind.bind_exact_effect_claim(**{**kwargs, "source": ea_forged, "projected": ea_forged})
