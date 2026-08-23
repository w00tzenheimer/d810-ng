"""Exact source/projected binding contracts for Task 9."""

from __future__ import annotations

import pytest

from d810.transforms.unflatten_authority import bind
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id, _claim_factory, _subject_factory
from .helpers import block_ref, exact_fixture
from .test_model import _valid_proposal


def _fixture():
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    catalog = proposal.source_identity_catalog
    return proposal, catalog


# Existing binding tests use the original private spelling as a compatibility
# alias; the implementation lives in the shared public helpers module.
_exact_fixture = exact_fixture


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


def test_inventory_binding_requires_exact_reachable_site_not_surviving_owner() -> None:
    _proposal, catalog = _fixture()
    owner = next(item for item in catalog.blocks if item.anchor_ea == 0x1300)
    effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=owner.block_ref,
        anchor_ea=owner.anchor_ea,
        locator=model.EffectSubjectLocator(
            owner.block_ref, owner.anchor_ea, 0x1300, model.EffectSiteKind.STORE,
        ),
    )
    terminal = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.TERMINAL,
        role=model.SemanticSubjectRole.TERMINAL_SITE,
        block_ref=owner.block_ref,
        anchor_ea=owner.anchor_ea,
        locator=model.TerminalSubjectLocator(
            owner.block_ref, owner.anchor_ea, model.TerminalKind.RETURN, 0x1300,
        ),
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    effect_row = model.InventoryEffectSite(
        1, owner.block_ref, owner.anchor_ea, 0, 0x1300,
        model.EffectSiteKind.STORE, 0x90, 4,
    )
    terminal_row = model.InventoryTerminalSite(
        1, owner.block_ref, owner.anchor_ea, 0, 0x1300,
        model.TerminalKind.RETURN,
    )
    absent = bind.bind_inventory_subjects(
        (effect, terminal), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("candidate-sites-missing"),
        generation=catalog.generation, serial_by_ref=serials,
        effects=(), terminals=(), reachable_serials=(1,),
    )
    assert {item.status for item in absent} == {model.SubjectBindingStatus.MISSING}
    present = bind.bind_inventory_subjects(
        (effect, terminal), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("candidate-sites-present"),
        generation=catalog.generation, serial_by_ref=serials,
        effects=(effect_row,), terminals=(terminal_row,), reachable_serials=(1,),
    )
    assert all(item.status is model.SubjectBindingStatus.UNIQUE for item in present)


def test_inventory_site_family_swaps_are_typed_rejections() -> None:
    _proposal, catalog = _fixture()
    owner = next(item for item in catalog.blocks if item.anchor_ea == 0x1300)
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=owner.block_ref, anchor_ea=owner.anchor_ea,
        locator=model.EffectSubjectLocator(
            owner.block_ref, owner.anchor_ea, 0x1300, model.EffectSiteKind.STORE,
        ),
    )
    effect = model.InventoryEffectSite(
        serials[owner.block_ref], owner.block_ref, owner.anchor_ea,
        0, 0x1300, model.EffectSiteKind.STORE, 0x90, 4,
    )
    terminal = model.InventoryTerminalSite(
        serials[owner.block_ref], owner.block_ref, owner.anchor_ea,
        0, 0x1300, model.TerminalKind.RETURN,
    )
    base = bind.bind_projected_subjects(
        (subject,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("family-swap"), generation=catalog.generation,
        serial_by_ref=serials,
    )[0]
    with pytest.raises(TypeError, match="effects"):
        model.resolve_inventory_site_binding(
            subject, base, effects=(terminal,), terminals=(effect,),
            reachable_serials=(serials[owner.block_ref],), serial_by_ref=serials,
        )
    with pytest.raises(TypeError, match="effects"):
        bind.bind_inventory_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("family-swap-binder"),
            generation=catalog.generation, serial_by_ref=serials,
            effects=(terminal,), terminals=(effect,),
            reachable_serials=(serials[owner.block_ref],),
        )


@pytest.mark.parametrize("site_kind", (model.EffectSiteKind.STORE, model.TerminalKind.RETURN))
def test_inventory_binding_rejects_site_rows_outside_owned_native_origins(site_kind: object) -> None:
    _proposal, catalog = _fixture()
    owner = next(item for item in catalog.blocks if item.anchor_ea == 0x1300)
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    site_ea = 0x1304 if site_kind is model.EffectSiteKind.STORE else 0x1308
    if site_kind is model.EffectSiteKind.STORE:
        subject = _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.EFFECT,
            role=model.SemanticSubjectRole.EFFECT_SITE,
            block_ref=owner.block_ref, anchor_ea=owner.anchor_ea,
            locator=model.EffectSubjectLocator(
                owner.block_ref, owner.anchor_ea, site_ea, site_kind,
            ),
        )
        effects = (model.InventoryEffectSite(
            serials[owner.block_ref], owner.block_ref, owner.anchor_ea,
            1, site_ea, site_kind, 0x90, 4,
        ),)
        terminals = ()
    else:
        subject = _subject_factory(
            model.SemanticSubjectRef,
            kind=model.SemanticSubjectKind.TERMINAL,
            role=model.SemanticSubjectRole.TERMINAL_SITE,
            block_ref=owner.block_ref, anchor_ea=owner.anchor_ea,
            locator=model.TerminalSubjectLocator(
                owner.block_ref, owner.anchor_ea, site_kind, site_ea,
            ),
        )
        effects = ()
        terminals = (model.InventoryTerminalSite(
            serials[owner.block_ref], owner.block_ref, owner.anchor_ea,
            1, site_ea, site_kind,
        ),)
    with pytest.raises(ValueError, match="site binding owner"):
        bind.bind_inventory_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("candidate-site-origin-gap"),
            generation=catalog.generation, serial_by_ref=serials,
            effects=effects, terminals=terminals,
            reachable_serials=(serials[owner.block_ref],),
        )


def test_inventory_binding_rejects_noncanonical_rows_and_owner_corruption() -> None:
    from dataclasses import replace
    from types import SimpleNamespace

    _proposal, catalog = _fixture()
    owner = next(item for item in catalog.blocks if item.anchor_ea == 0x1300)
    effect = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=owner.block_ref, anchor_ea=owner.anchor_ea,
        locator=model.EffectSubjectLocator(
            owner.block_ref, owner.anchor_ea, 0x1304, model.EffectSiteKind.STORE,
        ),
    )
    serials = {item.block_ref: index for index, item in enumerate(catalog.blocks)}
    row = model.InventoryEffectSite(
        serials[owner.block_ref], owner.block_ref, owner.anchor_ea, 1, 0x1304,
        model.EffectSiteKind.STORE, 0x90, 4,
    )
    kwargs = dict(
        catalog=catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=authority_id("invalid-site-input"),
        generation=catalog.generation, serial_by_ref=serials,
        terminals=(), reachable_serials=(serials[owner.block_ref],),
    )
    with pytest.raises(TypeError):
        bind.bind_inventory_subjects(
            (effect,),
            effects=(SimpleNamespace(
                owner_serial=row.owner_serial, owner_ref=row.owner_ref,
                owner_anchor_ea=row.owner_anchor_ea,
                instruction_ordinal=row.instruction_ordinal,
                instruction_ea=row.instruction_ea,
                effect_kind=row.effect_kind, opcode=row.opcode, width=row.width,
            ),),
            **kwargs,
        )
    class EffectSubclass(model.InventoryEffectSite):
        pass
    with pytest.raises(TypeError):
        bind.bind_inventory_subjects(
            (effect,), effects=(EffectSubclass(
                row.owner_serial, row.owner_ref, row.owner_anchor_ea,
                row.instruction_ordinal, row.instruction_ea, row.effect_kind,
                row.opcode, row.width,
            ),), **kwargs,
        )
    with pytest.raises(ValueError, match="owner serial"):
        bind.bind_inventory_subjects(
            (effect,),
            effects=(replace(row, owner_serial=serials[owner.block_ref] + 1),),
            **{**kwargs, "reachable_serials": (serials[owner.block_ref], serials[owner.block_ref] + 1)},
        )
    with pytest.raises(ValueError, match="foreign"):
        bind.bind_inventory_subjects(
            (effect,), effects=(replace(row, owner_ref=block_ref("foreign")),), **kwargs,
        )
    with pytest.raises(ValueError, match="reachable"):
        bind.bind_inventory_subjects(
            (effect,), effects=(row,), terminals=(), reachable_serials=(99,),
            catalog=catalog,
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("unreachable-site"),
            generation=catalog.generation, serial_by_ref=serials,
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


def test_canonical_route_binding_requires_live_conditional_instruction() -> None:
    """A matching anchor is insufficient when the branch was normalized away."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import InsnKind, InsnSnapshot

    source, proposal, _exclusion, _refs = _exact_fixture()
    branch_block = source.blocks[1]
    nop_branch = InsnSnapshot(0, 0x2001, (), kind=InsnKind.NOP)
    mutated = source.__class__(
        {
            **source.blocks,
            1: branch_block.__class__(
                serial=branch_block.serial,
                block_type=branch_block.block_type,
                succs=branch_block.succs,
                preds=branch_block.preds,
                flags=branch_block.flags,
                start_ea=branch_block.start_ea,
                insn_snapshots=(branch_block.insn_snapshots[0], nop_branch),
                kind=branch_block.kind,
            ),
        },
        source.entry_serial,
        source.func_ea,
    )

    assert bind_canonical_semantic_evidence(mutated, proposal.route_evidence) is None


def test_canonical_route_binding_rejects_unpermitted_carrier_interference() -> None:
    """A carrier corridor cannot acquire an additional live writer."""
    from d810.analyses.control_flow.semantic_route_evidence import (
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.expressions import ValueOpKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    branch_block = source.blocks[1]
    foreign_writer = InsnSnapshot(
        0,
        0x2000,
        (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    mutated = source.__class__(
        {
            **source.blocks,
            1: branch_block.__class__(
                serial=branch_block.serial,
                block_type=branch_block.block_type,
                succs=branch_block.succs,
                preds=branch_block.preds,
                flags=branch_block.flags,
                start_ea=branch_block.start_ea,
                insn_snapshots=(foreign_writer, branch_block.insn_snapshots[1]),
                kind=branch_block.kind,
            ),
        },
        source.entry_serial,
        source.func_ea,
    )

    assert bind_canonical_semantic_evidence(mutated, proposal.route_evidence) is None


def test_canonical_route_binding_rejects_independent_predicate_interference() -> None:
    """Predicate storage writers are replayed independently of carriers."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticPredicateProof,
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.expressions import ValueOpKind
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    route = proposal.route_evidence.route_proofs[0]
    predicate_storage = StorageIdentity(StorageIdentityKind.STACK, 8)
    predicate = SemanticPredicateProof(
        kind=route.predicate.kind,
        origin=route.predicate.origin,
        consumer=route.predicate.consumer,
        corridor=route.predicate.corridor,
        storage_identity=predicate_storage,
        width=4,
        compare_constant=7,
    )
    branch_block = source.blocks[1]
    predicate_writer = InsnSnapshot(
        0,
        0x2000,
        (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=99),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=8, stack_refs=(8,)),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    branch = replace(
        branch_block.insn_snapshots[1],
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=8, stack_refs=(8,)),
    )
    mutated = source.__class__(
        {
            **source.blocks,
            1: replace(branch_block, insn_snapshots=(predicate_writer, branch)),
        },
        source.entry_serial,
        source.func_ea,
    )
    evidence = replace(proposal.route_evidence, route_proofs=(replace(route, predicate=predicate),))

    assert bind_canonical_semantic_evidence(mutated, evidence) is None


@pytest.mark.parametrize("consumer_shape", ("nop", "storage", "width"))
def test_canonical_route_binding_requires_live_carrier_consumer(consumer_shape: str) -> None:
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import bind_canonical_semantic_evidence
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.expressions import ValueOpKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    block = source.blocks[1]
    if consumer_shape == "nop":
        consumer = InsnSnapshot(0, 0x2001, (), kind=InsnKind.NOP)
    else:
        width = 8 if consumer_shape == "width" else 4
        storage = 8 if consumer_shape == "storage" else 4
        consumer = InsnSnapshot(
            0,
            0x2001,
            (),
            r=MopSnapshot(kind=OperandKind.STACK, size=width, stkoff=storage, stack_refs=(storage,)),
            d=MopSnapshot(kind=OperandKind.REGISTER, size=width, reg=0),
            kind=InsnKind.LOAD,
            value_op_kind=ValueOpKind.LOAD,
        )
    mutated = source.__class__(
        {**source.blocks, 1: replace(block, insn_snapshots=(block.insn_snapshots[0], consumer))},
        source.entry_serial,
        source.func_ea,
    )

    assert bind_canonical_semantic_evidence(mutated, proposal.route_evidence) is None


def test_canonical_route_binding_accepts_extra_target_predecessor() -> None:
    """A valid reciprocal edge need not be the target's only predecessor."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        BoundCanonicalSemanticEvidence,
        bind_canonical_semantic_evidence,
    )

    source, proposal, _exclusion, _refs = _exact_fixture()
    target = source.blocks[2]
    mutated = source.__class__(
        {**source.blocks, 2: replace(target, preds=(1, 4))},
        source.entry_serial,
        source.func_ea,
    )

    assert isinstance(
        bind_canonical_semantic_evidence(mutated, proposal.route_evidence),
        BoundCanonicalSemanticEvidence,
    )


def test_canonical_route_binding_rejects_duplicate_carrier_writer_ea() -> None:
    """Ambiguous duplicate EAs cannot be skipped during write replay."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import bind_canonical_semantic_evidence
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.expressions import ValueOpKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    branch_block = source.blocks[1]
    duplicate = InsnSnapshot(
        0,
        0x2000,
        (),
        l=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=99),
        d=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
    )
    mutated = source.__class__(
        {
            **source.blocks,
            1: replace(
                branch_block,
                insn_snapshots=(branch_block.insn_snapshots[0], duplicate, branch_block.insn_snapshots[1]),
            ),
        },
        source.entry_serial,
        source.func_ea,
    )

    assert bind_canonical_semantic_evidence(mutated, proposal.route_evidence) is None


def test_canonical_route_binding_rejects_frankenstein_origin_branch() -> None:
    """An origin branch cannot be spliced onto a source with no live branch."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticCorridorPoint,
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import InsnKind, InsnSnapshot, MopSnapshot, OperandKind
    from d810.ir.semantics import PredicateKind

    source, proposal, _exclusion, refs = _exact_fixture()
    route = proposal.route_evidence.route_proofs[0]
    origin = SemanticCorridorPoint(refs[0].identity, 0x1001)
    predicate = replace(
        route.predicate,
        origin=origin,
        corridor=(origin, route.predicate.consumer),
    )
    origin_branch = InsnSnapshot(
        0,
        0x1001,
        (),
        l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=4, stack_refs=(4,)),
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=7),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=2),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    mutated = source.__class__(
        {
            **source.blocks,
            0: replace(source.blocks[0], insn_snapshots=(source.blocks[0].insn_snapshots[0], origin_branch)),
            1: replace(source.blocks[1], insn_snapshots=(source.blocks[1].insn_snapshots[0], InsnSnapshot(0, 0x2001, (), kind=InsnKind.NOP))),
        },
        source.entry_serial,
        source.func_ea,
    )
    evidence = replace(proposal.route_evidence, route_proofs=(replace(route, predicate=predicate),))

    assert bind_canonical_semantic_evidence(mutated, evidence) is None


def test_canonical_route_binding_accepts_exact_and_ownerless_routes() -> None:
    from d810.analyses.control_flow.semantic_route_evidence import (
        BoundCanonicalSemanticEvidence,
        bind_canonical_semantic_evidence,
    )

    for optional_owner in (False, True):
        source, proposal, _exclusion, _refs = _exact_fixture(
            optional_owner=optional_owner,
        )
        bound = bind_canonical_semantic_evidence(source, proposal.route_evidence)
        assert isinstance(bound, BoundCanonicalSemanticEvidence)
        assert len(bound.routes) == 1
        assert bound.routes[0].predicate is not None


def test_canonical_route_binding_accepts_normalized_ne_polarity() -> None:
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        BoundCanonicalSemanticEvidence,
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import MopSnapshot, OperandKind, PredicateKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    branch_block = source.blocks[1]
    branch = replace(
        branch_block.insn_snapshots[1],
        branch_predicate=PredicateKind.NE,
        predicate_kind=PredicateKind.NE,
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
    )
    source = source.__class__(
        {
            **source.blocks,
            1: replace(
                branch_block,
                insn_snapshots=(branch_block.insn_snapshots[0], branch),
            ),
        },
        source.entry_serial,
        source.func_ea,
    )
    bound = bind_canonical_semantic_evidence(source, proposal.route_evidence)
    assert isinstance(bound, BoundCanonicalSemanticEvidence)


def test_canonical_route_binding_accepts_independent_compare_and_state_values() -> None:
    """The branch literal is not required to equal a destination state."""
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        BoundCanonicalSemanticEvidence,
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import MopSnapshot, OperandKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    route = proposal.route_evidence.route_proofs[0]
    branch_block = source.blocks[1]
    branch = replace(
        branch_block.insn_snapshots[1],
        r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=0),
    )
    source = source.__class__(
        {
            **source.blocks,
            1: replace(branch_block, insn_snapshots=(branch_block.insn_snapshots[0], branch)),
        },
        source.entry_serial,
        source.func_ea,
    )
    evidence = replace(
        proposal.route_evidence,
        route_proofs=(replace(route, predicate=replace(route.predicate, compare_constant=0)),),
    )

    bound = bind_canonical_semantic_evidence(source, evidence)
    assert isinstance(bound, BoundCanonicalSemanticEvidence)


@pytest.mark.parametrize(
    "mutation",
    (
        "predicate",
        "storage",
        "width",
        "constant",
        "target",
        "role",
        "topology",
        "predicate_ea",
        "state_write_ea",
    ),
)
def test_canonical_route_binding_rejects_adversarial_live_semantics(mutation) -> None:
    from dataclasses import replace

    from d810.analyses.control_flow.semantic_route_evidence import (
        bind_canonical_semantic_evidence,
    )
    from d810.ir.flowgraph import MopSnapshot, OperandKind, PredicateKind

    source, proposal, _exclusion, _refs = _exact_fixture()
    route = proposal.route_evidence.route_proofs[0]
    branch = source.blocks[1].insn_snapshots[1]
    if mutation == "predicate":
        branch = replace(
            branch,
            branch_predicate=PredicateKind.NE,
            predicate_kind=PredicateKind.NE,
        )
    elif mutation == "storage":
        branch = replace(
            branch,
            l=MopSnapshot(kind=OperandKind.STACK, size=4, stkoff=8, stack_refs=(8,)),
        )
    elif mutation == "width":
        branch = replace(
            branch,
            l=MopSnapshot(kind=OperandKind.STACK, size=8, stkoff=4, stack_refs=(4,)),
            r=MopSnapshot(kind=OperandKind.NUMBER, size=8, value=7),
        )
    elif mutation == "constant":
        branch = replace(
            branch,
            r=MopSnapshot(kind=OperandKind.NUMBER, size=4, value=8),
        )
    elif mutation == "target":
        branch = replace(
            branch,
            d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=3),
        )
    elif mutation == "role":
        route = replace(
            route,
            destinations=(
                replace(
                    route.destinations[0],
                    role=route.destinations[1].role,
                ),
                replace(
                    route.destinations[1],
                    role=route.destinations[0].role,
                ),
            ),
        )
    elif mutation == "topology":
        block = source.blocks[0]
        source = source.__class__(
            {
                **source.blocks,
                0: replace(block, succs=()),
            },
            source.entry_serial,
            source.func_ea,
        )
    elif mutation == "predicate_ea":
        branch = replace(
            branch,
            ea=0x2002,
        )
    elif mutation == "state_write_ea":
        route = replace(
            route,
            state_write=replace(
                route.state_write,
                instruction_ea=0x1001,
                corridor_instruction_eas=(0x1001, 0x2000),
            ),
        )
    if mutation in {"predicate", "storage", "width", "constant", "target", "predicate_ea"}:
        block = source.blocks[1]
        source = source.__class__(
            {
                **source.blocks,
                1: replace(block, insn_snapshots=(block.insn_snapshots[0], branch)),
            },
            source.entry_serial,
            source.func_ea,
        )
    evidence = replace(proposal.route_evidence, route_proofs=(route,))

    assert bind_canonical_semantic_evidence(source, evidence) is None


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


def test_exact_effect_binding_uses_shared_call_predicate_resolver() -> None:
    from dataclasses import replace
    from d810.ir.flowgraph import InsnKind
    from d810.ir.semantics import CallKind
    from d810.transforms.unflatten_authority import producer_api

    source, proposal, exclusion, refs = _exact_fixture()
    discarded_block = source.blocks[exclusion.discarded_effect_serial]
    call_by_predicate = replace(
        discarded_block.insn_snapshots[0],
        kind=InsnKind.NOP,
        is_call=False,
        call_kind=CallKind.DIRECT,
    )
    source_with_predicate_call = replace(
        source,
        blocks={
            **source.blocks,
            discarded_block.serial: replace(
                discarded_block, insn_snapshots=(call_by_predicate,)
            ),
        },
    )
    result = producer_api._exact_effect_claim(
        exclusion=exclusion, source=source_with_predicate_call,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=refs,
        canonical_route_evidence=proposal.route_evidence,
        state_identity=proposal.plan_inputs.state_identity,
    )
    assert result.discarded_effect_ea == exclusion.discarded_effect_ea
