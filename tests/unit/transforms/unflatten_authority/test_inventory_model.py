from __future__ import annotations

from dataclasses import replace

import pytest

from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef, PlanBlockRef
from d810.ir.semantics import ControlTransferKind
from d810.ir.flowgraph import InsnKind
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import StableBlockIdentity
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import (
    _subject_factory,
    authority_id,
    canonical_bytes,
    canonical_decode,
    semantic_graph_inventory_digest,
)


def _inventory(**overrides: object) -> model.SemanticGraphInventory:
    values: dict[str, object] = {
        "phase": model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        "graph_fingerprint": authority_id("graph"),
        "generation": 3,
        "blocks": (),
        "subjects": (),
        "bindings": (),
        "effects": (),
        "terminals": (),
        "topology": (),
    }
    values.update(overrides)
    if "reachable_serials" not in values:
        values["reachable_serials"] = tuple(item.serial for item in values["blocks"])
    if "entry_serial" not in values:
        values["entry_serial"] = min(values["blocks"], key=lambda item: item.serial).serial if values["blocks"] else 0
    if "source_subject_ids" not in values:
        values["source_subject_ids"] = tuple(item.subject_id for item in values["subjects"])
    values["inventory_digest"] = semantic_graph_inventory_digest(
        values["phase"], values["graph_fingerprint"], values["generation"],
        values["blocks"], values["subjects"], values["bindings"],
        values["effects"], values["terminals"], values["topology"],
        values["reachable_serials"],
        values["entry_serial"], values["source_subject_ids"],
    )
    return model.SemanticGraphInventory(**values)


def _obs(
    ordinal: int,
    instruction_ea: int | None,
    opcode: int,
    width: int,
    kind: InsnKind = InsnKind.NOP,
    control_transfer_kind: ControlTransferKind | None = None,
    is_call: bool = False,
    call_kind: object | None = None,
) -> model.InventoryInstructionObservation:
    return model.InventoryInstructionObservation(
        ordinal, instruction_ea, opcode, width, kind,
        control_transfer_kind, is_call, call_kind,
    )


def test_inventory_records_are_closed_and_round_trip_canonically() -> None:
    ref = PlanBlockRef("plan", "block")
    ref2 = PlanBlockRef("plan", "block2")
    block = model.InventoryBlockObservation(
        1, ref, 0x1000, (0x1000, 0x1004), (), (2,), 0x1004,
        (
            _obs(0, 0x1000, 0x42, 4, InsnKind.STORE),
            _obs(1, 0x1004, 0x43, 0, InsnKind.GOTO, ControlTransferKind.GOTO),
        ),
    )
    block2 = model.InventoryBlockObservation(
        2, ref2, 0x2000, (0x2000,), (1,), (), None,
        (_obs(0, 0x2000, 0, 0),),
        model.BlockKind.STOP,
    )
    effect = model.InventoryEffectSite(
        1, ref, 0x1000, 0, 0x1000, model.EffectSiteKind.STORE, 0x42, 4,
    )
    terminal = model.InventoryTerminalSite(
        2, ref2, 0x2000, None, 0x2000, model.TerminalKind.STOP,
    )
    incidence = model.InventoryTopologyIncidence(
        model.TopologyIncidenceKind.SUCCESSOR, 1, 2, 0x1004,
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=ref, anchor_ea=0x1000,
        locator=model.BlockSubjectLocator(ref, 0x1000),
    )
    effect_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=ref, anchor_ea=0x1000,
        locator=model.EffectSubjectLocator(ref, 0x1000, 0x1000, model.EffectSiteKind.STORE),
    )
    terminal_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.TERMINAL,
        role=model.SemanticSubjectRole.TERMINAL_SITE,
        block_ref=ref2, anchor_ea=0x2000,
        locator=model.TerminalSubjectLocator(ref2, 0x2000, model.TerminalKind.STOP, 0x2000),
    )
    subjects = tuple(sorted((subject, effect_subject, terminal_subject), key=lambda item: item.subject_id))
    bindings = tuple(
        model.PhaseSubjectBinding(
            item, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            item.block_ref, authority_id("graph"), 3,
            model.SubjectBindingStatus.UNIQUE,
            1 if item.block_ref == ref else 2,
            item.anchor_ea,
            (0x1000, 0x1004) if item.block_ref == ref else (0x2000,),
            item.role,
        )
        for item in subjects
    )
    inventory = _inventory(
        blocks=(block, block2), subjects=subjects, bindings=bindings,
        effects=(effect,), terminals=(terminal,),
        topology=(model.InventoryTopologyIncidence(model.TopologyIncidenceKind.PREDECESSOR, 2, 1, 0x1004), incidence),
    )
    encoded = canonical_bytes(inventory)
    decoded = canonical_decode(encoded)
    assert type(decoded) is model.SemanticGraphInventory
    assert decoded == inventory
    assert canonical_bytes(decoded) == encoded

    effect_binding = next(
        item for item in inventory.bindings
        if item.subject.role is model.SemanticSubjectRole.EFFECT_SITE
    )
    object.__setattr__(inventory, "effects", ())
    with pytest.raises(ValueError, match="site binding"):
        model.validate_semantic_graph_inventory(inventory)
    object.__setattr__(inventory, "effects", (effect,))
    missing_binding = replace(
        effect_binding,
        block_ref=None,
        status=model.SubjectBindingStatus.MISSING,
        serial=None,
        anchor_ea=None,
        native_instruction_eas=(),
    )
    object.__setattr__(
        inventory,
        "bindings",
        tuple(missing_binding if item is effect_binding else item for item in inventory.bindings),
    )
    with pytest.raises(ValueError, match="site binding"):
        model.validate_semantic_graph_inventory(inventory)


def test_inventory_rejects_wrong_rows_and_noncanonical_collections() -> None:
    class IntSubclass(int):
        pass

    with pytest.raises(TypeError):
        model.InventoryBlockObservation(IntSubclass(1), None, 1, (), (), (), None)
    with pytest.raises((TypeError, ValueError)):
        model.InventoryBlockObservation(True, None, 1, (), (), (), None)
    with pytest.raises((TypeError, ValueError)):
        model.InventoryBlockObservation(1, object(), 1, (), (), (), None)
    with pytest.raises((TypeError, ValueError)):
        model.InventoryEffectSite(1, None, 1, 0, 1, model.EffectSiteKind.STORE, True, 0)
    with pytest.raises((TypeError, ValueError)):
        model.InventoryTerminalSite(1, None, 1, 0, 1, model.TerminalKind.STOP)
    with pytest.raises((TypeError, ValueError)):
        model.InventoryTopologyIncidence(model.TopologyIncidenceKind.SUCCESSOR, True, 1, None)

    block = model.InventoryBlockObservation(
        1, None, 1, (1,), (2,), (), None,
        (_obs(0, 1, 0, 0),),
    )
    with pytest.raises(ValueError, match="sorted"):
        _inventory(blocks=(replace(block, native_instruction_eas=(2, 1)),))
    with pytest.raises(ValueError, match="unique|duplicate"):
        _inventory(blocks=(block, block))


def test_inventory_rejects_duplicate_non_none_block_refs() -> None:
    ref = PlanBlockRef("plan", "duplicate-ref")
    first = model.InventoryBlockObservation(
        1, ref, 1, (1,), (), (2,), 1,
        (_obs(0, 1, 0, 0, InsnKind.GOTO, ControlTransferKind.GOTO),),
    )
    second = model.InventoryBlockObservation(
        2, ref, 2, (2,), (1,), (), None,
        (_obs(0, 2, 0, 0),),
    )
    topology = (
        model.InventoryTopologyIncidence(
            model.TopologyIncidenceKind.PREDECESSOR, 2, 1, 1,
        ),
        model.InventoryTopologyIncidence(
            model.TopologyIncidenceKind.SUCCESSOR, 1, 2, 1,
        ),
    )
    with pytest.raises(ValueError, match="duplicate block reference"):
        _inventory(blocks=(first, second), topology=topology)

    valid = _inventory(
        blocks=(first, replace(second, block_ref=None)), topology=topology,
    )
    object.__setattr__(valid, "blocks", (first, second))
    with pytest.raises(ValueError, match="invalid record value"):
        canonical_decode(canonical_bytes(valid))


def test_inventory_revalidates_nested_rows_and_explicit_reachability_closure() -> None:
    first = model.InventoryBlockObservation(1, None, 1, (), (), (), None)
    unreachable = model.InventoryBlockObservation(2, None, 2, (), (), (), None)
    inventory = _inventory(blocks=(first, unreachable), reachable_serials=(1,))
    assert inventory.reachable_serials == (1,)
    assert canonical_decode(canonical_bytes(inventory)) == inventory

    object.__setattr__(inventory.blocks[0], "graph_start_ea", 3)
    with pytest.raises((TypeError, ValueError)):
        model.validate_semantic_graph_inventory(inventory)
    object.__setattr__(inventory.blocks[0], "graph_start_ea", 1)
    object.__setattr__(inventory, "inventory_digest", authority_id("forged"))
    with pytest.raises((TypeError, ValueError)):
        model.validate_semantic_graph_inventory(inventory)


def test_inventory_entry_serial_proves_the_raw_successor_closure() -> None:
    first = model.InventoryBlockObservation(1, None, 1, (), (), (2,), None)
    second = model.InventoryBlockObservation(2, None, 2, (), (1,), (), None)
    inventory = _inventory(
        blocks=(first, second), reachable_serials=(1, 2), entry_serial=1,
        topology=(
            model.InventoryTopologyIncidence(model.TopologyIncidenceKind.PREDECESSOR, 2, 1, None),
            model.InventoryTopologyIncidence(model.TopologyIncidenceKind.SUCCESSOR, 1, 2, None),
        ),
    )
    object.__setattr__(inventory, "entry_serial", 2)
    with pytest.raises((TypeError, ValueError), match="closure|reachable"):
        model.validate_semantic_graph_inventory(inventory)
    object.__setattr__(inventory, "entry_serial", True)
    with pytest.raises((TypeError, ValueError), match="entry_serial"):
        model.validate_semantic_graph_inventory(inventory)


def test_producer_site_subjects_equal_reachable_raw_site_locators() -> None:
    ref = LogicalBlockRef("producer", "one", 1)
    block = model.InventoryBlockObservation(
        1, ref, 0x1000, (0x1000,), (), (), None,
        (_obs(0, 0x1000, 0x90, 4, InsnKind.STORE),),
    )
    effect = model.InventoryEffectSite(
        1, ref, 0x1000, 0, 0x1000, model.EffectSiteKind.STORE, 0x90, 4,
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=ref, anchor_ea=0x1000,
        locator=model.EffectSubjectLocator(
            ref, 0x1000, 0x1000, model.EffectSiteKind.STORE,
        ),
    )
    fingerprint = authority_id("producer-sites")
    binding = model.PhaseSubjectBinding(
        subject, model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        ref, fingerprint, 3, model.SubjectBindingStatus.UNIQUE,
        1, 0x1000, (0x1000,), subject.role,
    )
    inventory = _inventory(
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        graph_fingerprint=fingerprint, blocks=(block,), subjects=(subject,),
        bindings=(binding,), effects=(effect,), reachable_serials=(1,),
        entry_serial=1, source_subject_ids=(subject.subject_id,),
    )
    assert inventory.subjects == (subject,)
    object.__setattr__(inventory, "subjects", ())
    with pytest.raises((TypeError, ValueError)):
        model.validate_semantic_graph_inventory(inventory)


def test_inventory_rejects_missing_successor_and_empty_default_closure() -> None:
    dangling = model.InventoryBlockObservation(1, None, 1, (), (), (99,), None)
    with pytest.raises((TypeError, ValueError), match="successor|absent"):
        _inventory(blocks=(dangling,), reachable_serials=(1,))
    with pytest.raises(TypeError):
        model.SemanticGraphInventory(
            phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            graph_fingerprint=authority_id("empty-default"), generation=3,
            blocks=(), subjects=(), bindings=(), effects=(), terminals=(),
            topology=(), inventory_digest=authority_id("digest"),
        )

def test_unique_binding_must_own_a_closed_inventory_block() -> None:
    ref = PlanBlockRef("plan", "planned-helper")
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.PLANNED_HELPER,
        block_ref=ref,
        anchor_ea=1,
        locator=model.BlockSubjectLocator(ref, 1),
    )
    binding = model.PhaseSubjectBinding(
        subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ref,
        authority_id("graph"), 3, model.SubjectBindingStatus.UNIQUE,
        99, 1, (1,), model.SemanticSubjectRole.PLANNED_HELPER,
    )
    with pytest.raises(ValueError, match="serial|block"):
        _inventory(
            blocks=(model.InventoryBlockObservation(1, None, 1, (), (), (), None),),
            subjects=(subject,), bindings=(binding,),
        )


def test_inventory_digest_covers_every_preceding_field() -> None:
    ref = PlanBlockRef("plan", "block")
    block = model.InventoryBlockObservation(
        1, ref, 1, (1,), (), (), None,
            (_obs(0, 1, 1, 0, InsnKind.STORE),),
        model.BlockKind.STOP,
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=ref,
        anchor_ea=1,
        locator=model.BlockSubjectLocator(ref, 1),
    )
    binding = model.PhaseSubjectBinding(
        subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ref,
        authority_id("graph"), 3, model.SubjectBindingStatus.UNIQUE, 1, 1, (1,),
        model.SemanticSubjectRole.SOURCE_ENTRY,
    )
    effect_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.EFFECT,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=ref, anchor_ea=1,
        locator=model.EffectSubjectLocator(ref, 1, 1, model.EffectSiteKind.STORE),
    )
    terminal_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.TERMINAL,
        role=model.SemanticSubjectRole.TERMINAL_SITE,
        block_ref=ref, anchor_ea=1,
        locator=model.TerminalSubjectLocator(ref, 1, model.TerminalKind.STOP, 1),
    )
    effect_binding = model.PhaseSubjectBinding(
        effect_subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ref,
        authority_id("graph"), 3, model.SubjectBindingStatus.UNIQUE, 1, 1, (1,),
        model.SemanticSubjectRole.EFFECT_SITE,
    )
    terminal_binding = model.PhaseSubjectBinding(
        terminal_subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ref,
        authority_id("graph"), 3, model.SubjectBindingStatus.UNIQUE, 1, 1, (1,),
        model.SemanticSubjectRole.TERMINAL_SITE,
    )
    effect = model.InventoryEffectSite(1, ref, 1, 0, 1, model.EffectSiteKind.STORE, 1, 0)
    terminal = model.InventoryTerminalSite(1, ref, 1, None, 1, model.TerminalKind.STOP)
    inventory = _inventory(
        blocks=(block,),
        subjects=tuple(sorted((subject, effect_subject, terminal_subject), key=lambda item: item.subject_id)),
        bindings=tuple(sorted((binding, effect_binding, terminal_binding), key=lambda item: item.subject.subject_id)),
        effects=(effect,), terminals=(terminal,),
    )
    for field_name, replacement in (
        ("graph_fingerprint", authority_id("other-graph")),
        ("generation", 4),
            ("blocks", (model.InventoryBlockObservation(
                1, ref, 1, (2,), (), (), None,
                (_obs(0, 2, 0, 0),),
            ),)),
        ("effects", (model.InventoryEffectSite(1, ref, 1, 0, 2, model.EffectSiteKind.STORE, 1, 0),)),
        ("terminals", (model.InventoryTerminalSite(1, ref, 1, None, 2, model.TerminalKind.STOP),)),
    ):
        values = {name: getattr(inventory, name) for name in inventory.__dataclass_fields__}
        values[field_name] = replacement
        with pytest.raises((TypeError, ValueError)):
            model.SemanticGraphInventory(**values)
    forged = object.__new__(model.SemanticGraphInventory)
    for name in inventory.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(inventory, name))
    object.__setattr__(forged, "inventory_digest", authority_id("forged"))
    with pytest.raises(ValueError, match="digest"):
        model.SemanticGraphInventory.__post_init__(forged)


def test_inventory_retains_foreign_predecessor_incidence_for_drift_evidence() -> None:
    block = model.InventoryBlockObservation(1, None, 1, (), (99,), (), None)
    incidence = model.InventoryTopologyIncidence(
        model.TopologyIncidenceKind.PREDECESSOR, 1, 99, None,
    )
    inventory = _inventory(blocks=(block,), topology=(incidence,))
    assert inventory.topology == (incidence,)


def test_unique_binding_must_match_its_inventory_block_row() -> None:
    ref = PlanBlockRef("plan", "block")
    block = model.InventoryBlockObservation(
        1, ref, 1, (1,), (), (), None,
        (_obs(0, 1, 0, 0),),
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=ref,
        anchor_ea=1,
        locator=model.BlockSubjectLocator(ref, 1),
    )
    binding = model.PhaseSubjectBinding(
        subject, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ref,
        authority_id("graph"), 3, model.SubjectBindingStatus.UNIQUE, 2, 1, (1,),
        model.SemanticSubjectRole.SOURCE_ENTRY,
    )
    with pytest.raises(ValueError, match="serial|block"):
        _inventory(blocks=(block,), subjects=(subject,), bindings=(binding,))


def test_binding_subjects_roundtrip_as_equal_distinct_records() -> None:
    ref = PlanBlockRef("plan", "block")
    block = model.InventoryBlockObservation(
        1, ref, 1, (1,), (), (), None,
        (_obs(0, 1, 0, 0),),
    )
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=ref, anchor_ea=1, locator=model.BlockSubjectLocator(ref, 1),
    )
    subject_copy = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=ref, anchor_ea=1, locator=model.BlockSubjectLocator(ref, 1),
    )
    assert subject_copy == subject and subject_copy is not subject
    binding = model.PhaseSubjectBinding(
        subject_copy, model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ref,
        authority_id("graph"), 3, model.SubjectBindingStatus.UNIQUE, 1, 1, (1,),
        model.SemanticSubjectRole.SOURCE_ENTRY,
    )
    inventory = _inventory(blocks=(block,), subjects=(subject,), bindings=(binding,))
    encoded = canonical_bytes(inventory)
    decoded = canonical_decode(encoded)
    assert type(decoded) is model.SemanticGraphInventory
    assert canonical_bytes(decoded) == encoded
    assert decoded.bindings[0].subject == decoded.subjects[0]
    assert decoded.bindings[0].subject is not decoded.subjects[0]

    corrupted = decoded.bindings[0].subject
    object.__setattr__(corrupted, "anchor_ea", 2)
    with pytest.raises((TypeError, ValueError)):
        model.SemanticGraphInventory.__post_init__(decoded)


def test_inventory_revalidates_nested_refs_and_rejects_plan_refs_in_producer() -> None:
    ref = PlanBlockRef("plan", "block")
    corrupted = object.__new__(PlanBlockRef)
    object.__setattr__(corrupted, "plan_id", "")
    object.__setattr__(corrupted, "local_block_id", ref.local_block_id)
    with pytest.raises((TypeError, ValueError)):
        block = model.InventoryBlockObservation(1, corrupted, 1, (), (), (), None)
        _inventory(blocks=(block,))

    with pytest.raises((TypeError, ValueError)):
        model.SemanticGraphInventory(
            phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
            graph_fingerprint=authority_id("graph"), generation=3,
            blocks=(model.InventoryBlockObservation(1, ref, 1, (), (), (), None),),
            subjects=(), bindings=(), effects=(), terminals=(), topology=(),
            inventory_digest=semantic_graph_inventory_digest(
                model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
                authority_id("graph"), 3,
                (model.InventoryBlockObservation(1, ref, 1, (), (), (), None),),
                (), (), (), (), (), (1,), 1, (),
            ),
            reachable_serials=(1,), entry_serial=1, source_subject_ids=(),
        )


def test_inventory_rejects_unbound_site_ordinals_and_transfer_eas() -> None:
    with pytest.raises(ValueError):
        model.InventoryBlockObservation(1, None, 0x1000, (0x1000,), (), (), 0x2000)
    block = model.InventoryBlockObservation(1, None, 0x1000, (), (), (), None)
    effect = model.InventoryEffectSite(1, None, 0x1000, 99, 0x3000, model.EffectSiteKind.STORE, 1, 0)
    terminal = model.InventoryTerminalSite(1, None, 0x1000, None, 0x4000, model.TerminalKind.STOP)
    with pytest.raises(ValueError):
        _inventory(blocks=(block,), effects=(effect,), terminals=(terminal,))


def test_inventory_instruction_rows_separate_order_from_unique_native_identity() -> None:
    instructions = (
        _obs(0, None, 1, 0),
        _obs(1, 0x1000, 2, 4, InsnKind.STORE),
    )
    block = model.InventoryBlockObservation(
        1, None, 0x1000, (0x1000,), (), (), None, instructions,
    )
    effect = model.InventoryEffectSite(1, None, 0x1000, 1, 0x1000, model.EffectSiteKind.STORE, 2, 4)
    inventory = _inventory(blocks=(block,), effects=(effect,))
    assert inventory.blocks[0].instruction_observations == instructions


def test_inventory_requires_effect_and_terminal_rows_for_instruction_observations() -> None:
    store = _obs(0, 0x1000, 2, 4, InsnKind.STORE)
    block = model.InventoryBlockObservation(1, None, 0x1000, (0x1000,), (), (), None, (store,))
    with pytest.raises(ValueError):
        _inventory(blocks=(block,))

    returned = _obs(0, 0x1000, 2, 4, InsnKind.RET, ControlTransferKind.RETURN)
    block = model.InventoryBlockObservation(1, None, 0x1000, (0x1000,), (), (), 0x1000, (returned,))
    effect = model.InventoryEffectSite(1, None, 0x1000, 0, 0x1000, model.EffectSiteKind.RETURN, 2, 4)
    with pytest.raises(ValueError):
        _inventory(blocks=(block,), effects=(effect,))
    with pytest.raises(ValueError):
        _inventory(blocks=(block,))


def test_inventory_stop_and_transfer_are_bound_to_block_facts() -> None:
    ordinary = model.InventoryBlockObservation(1, None, 0x1000, (), (), (), None, (), model.BlockKind.UNKNOWN)
    stop = model.InventoryBlockObservation(2, None, 0x2000, (), (), (), None, (), model.BlockKind.STOP)
    stop_row = model.InventoryTerminalSite(2, None, 0x2000, None, 0x2000, model.TerminalKind.STOP)
    with pytest.raises(ValueError):
        _inventory(blocks=(ordinary,), terminals=(stop_row,))
    with pytest.raises(ValueError):
        _inventory(blocks=(stop,), terminals=())

    store = _obs(0, 0x3000, 1, 0, InsnKind.STORE)
    with pytest.raises(ValueError):
        model.InventoryBlockObservation(
            3, None, 0x3000, (0x3000,), (), (), 0x3000, (store,), model.BlockKind.UNKNOWN,
        )


def test_inventory_replays_classifier_stop_tail_and_noreturn_context() -> None:
    rows = (
        _obs(0, 0x1000, 1, 0, InsnKind.TRAP),
        _obs(1, 0x1004, 2, 0),
    )
    block = model.InventoryBlockObservation(1, None, 0x1000, (0x1000, 0x1004), (), (), None, rows, model.BlockKind.STOP)
    effect = model.InventoryEffectSite(1, None, 0x1000, 0, 0x1000, model.EffectSiteKind.TRAP, 1, 0)
    terminals = (
        model.InventoryTerminalSite(1, None, 0x1000, 0, 0x1000, model.TerminalKind.TRAP),
        model.InventoryTerminalSite(1, None, 0x1000, None, 0x1000, model.TerminalKind.STOP),
    )
    assert _inventory(blocks=(block,), effects=(effect,), terminals=terminals).terminals == terminals

    call = _obs(0, 0x2000, 3, 0, InsnKind.CALL)
    call_block = model.InventoryBlockObservation(2, None, 0x2000, (0x2000,), (), (), None, (call,))
    call_effect = model.InventoryEffectSite(2, None, 0x2000, 0, 0x2000, model.EffectSiteKind.CALL, 3, 0)
    with pytest.raises(ValueError):
        _inventory(blocks=(call_block,), effects=(call_effect,))

    non_tail = (
        _obs(0, 0x3000, 3, 0, InsnKind.CALL),
        _obs(1, 0x3004, 4, 0),
    )
    non_tail_block = model.InventoryBlockObservation(
        3, None, 0x3000, (0x3000, 0x3004), (), (), None, non_tail,
    )
    non_tail_effect = model.InventoryEffectSite(3, None, 0x3000, 0, 0x3000, model.EffectSiteKind.CALL, 3, 0)
    non_tail_terminal = model.InventoryTerminalSite(3, None, 0x3000, 0, 0x3000, model.TerminalKind.NORETURN_CALL)
    with pytest.raises(ValueError):
        _inventory(blocks=(non_tail_block,), effects=(non_tail_effect,), terminals=(non_tail_terminal,))


def test_inventory_requires_instruction_rows_for_native_origins_and_mapped_anchor() -> None:
    with pytest.raises(ValueError):
        model.InventoryBlockObservation(1, None, 1, (1,), (), (), None)
    ref = LogicalBlockRef("session", "proxy", 1)
    instruction = _obs(0, 1, 0, 0)
    block = model.InventoryBlockObservation(1, ref, 2, (1,), (), (), None, (instruction,))
    phase = model.UnflattenAuthorityPhase.PRODUCER_FORECAST
    fingerprint = authority_id("graph")
    digest = semantic_graph_inventory_digest(phase, fingerprint, 3, (block,), (), (), (), (), (), (1,), 1, ())
    with pytest.raises(ValueError):
        model.SemanticGraphInventory(
            phase, fingerprint, 3, (block,), (), (), (), (), (), digest, (1,), 1, (),
        )


def test_inventory_revalidates_nested_native_identity_graph() -> None:
    key = NativePreanalysisKey("input", "x86", 64, 0, "function", "profile", "sdk")
    identity = StableBlockIdentity.from_instruction_eas((1,), native_key=key)
    ref = NativeBlockRef(identity)
    instruction = _obs(0, 1, 0, 0)
    block = model.InventoryBlockObservation(1, ref, 1, (1,), (), (), None, (instruction,))
    phase = model.UnflattenAuthorityPhase.PRODUCER_FORECAST
    fingerprint = authority_id("graph")
    digest = semantic_graph_inventory_digest(phase, fingerprint, 3, (block,), (), (), (), (), (), (1,), 1, ())
    object.__setattr__(key, "input_identity", "")
    with pytest.raises((TypeError, ValueError)):
        model.SemanticGraphInventory(
            phase, fingerprint, 3, (block,), (), (), (), (), (), digest, (1,), 1, (),
        )


def test_inventory_rejects_native_identity_bool_before_normalization() -> None:
    key = NativePreanalysisKey("input", "x86", 64, 0, "function", "profile", "sdk")
    identity = StableBlockIdentity.from_instruction_eas((1,), native_key=key)
    ref = NativeBlockRef(identity)
    block = model.InventoryBlockObservation(1, ref, 1, (1,), (), (), None, (_obs(0, 1, 0, 0),))
    phase = model.UnflattenAuthorityPhase.PRODUCER_FORECAST
    fingerprint = authority_id("graph")
    digest = semantic_graph_inventory_digest(phase, fingerprint, 3, (block,), (), (), (), (), (), (1,), 1, ())
    object.__setattr__(identity, "exact_instruction_eas", frozenset({True}))
    with pytest.raises((TypeError, ValueError)):
        model.SemanticGraphInventory(
            phase, fingerprint, 3, (block,), (), (), (), (), (), digest, (1,), 1, (),
        )
    assert type(next(iter(identity.exact_instruction_eas))) is bool


@pytest.mark.parametrize(
    "phase",
    (
        model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    ),
)
def test_inventory_rejects_native_interval_outside_domain_in_every_phase(
    phase: model.UnflattenAuthorityPhase,
) -> None:
    key = NativePreanalysisKey("input", "x86", 64, 0, "function", "profile", "sdk")
    identity = StableBlockIdentity.from_instruction_eas((1,), native_key=key)
    ref = NativeBlockRef(identity)
    block = model.InventoryBlockObservation(1, ref, 1, (1,), (), (), None, (_obs(0, 1, 0, 0),))
    object.__setattr__(identity.native_ranges.intervals[0], "end_ea", 0xFFFFFFFFFFFFFFFF + 1)
    with pytest.raises((TypeError, ValueError)):
        model.resolve_inventory_block_sites(
            serial=1,
            owner_ref=ref,
            owner_anchor_ea=1,
            block_kind=model.BlockKind.UNKNOWN,
            successor_serials=(),
            instruction_observations=(_obs(0, 1, 0, 0),),
        )
    fingerprint = authority_id("graph")
    digest = semantic_graph_inventory_digest(phase, fingerprint, 3, (block,), (), (), (), (), (), (1,), 1, ())
    with pytest.raises((TypeError, ValueError)):
        model.SemanticGraphInventory(
            phase, fingerprint, 3, (block,), (), (), (), (), (), digest, (1,), 1, (),
        )


def test_inventory_resolver_revalidates_direct_inputs_and_context() -> None:
    observation = _obs(0, 1, 0, 0)
    object.__setattr__(observation, "is_call", 1)
    with pytest.raises((TypeError, ValueError)):
        model.resolve_inventory_instruction(observation, is_tail=True, has_successors=False)
    with pytest.raises(TypeError):
        model.resolve_inventory_block_sites(
            serial=1, owner_ref=object(), owner_anchor_ea=1,
            block_kind=model.BlockKind.UNKNOWN, successor_serials=(),
            instruction_observations=(),
        )
    with pytest.raises((TypeError, ValueError)):
        model.resolve_inventory_block_sites(
            serial=1, owner_ref=None, owner_anchor_ea=1,
            block_kind=model.BlockKind.UNKNOWN, successor_serials=(True,),
            instruction_observations=(),
        )


@pytest.mark.parametrize("kind", (InsnKind.RET, InsnKind.GOTO))
def test_inventory_resolver_rejects_erased_raw_transfer_marker(kind: InsnKind) -> None:
    observation = _obs(0, 1, 0, 0, kind)
    with pytest.raises(ValueError, match="requires control transfer"):
        model.resolve_inventory_instruction(observation, is_tail=True, has_successors=False)


@pytest.mark.parametrize("kind", (InsnKind.NOP, InsnKind.STORE, InsnKind.CALL))
def test_inventory_resolver_rejects_foreign_transfer_marker(kind: InsnKind) -> None:
    observation = _obs(0, 1, 0, 0, kind, ControlTransferKind.GOTO)
    with pytest.raises(ValueError, match="must not carry control transfer"):
        model.resolve_inventory_instruction(observation, is_tail=True, has_successors=False)


@pytest.mark.parametrize("transfer", (ControlTransferKind.GOTO, ControlTransferKind.RETURN))
def test_inventory_unknown_kind_accepts_recovered_transfer(transfer: ControlTransferKind) -> None:
    observation = _obs(0, 1, 0, 0, InsnKind.UNKNOWN, transfer)
    model.resolve_inventory_instruction(observation, is_tail=True, has_successors=False)


def test_inventory_native_identity_is_correlated_in_every_phase() -> None:
    key = NativePreanalysisKey("input", "x86", 64, 0, "function", "profile", "sdk")
    ref = NativeBlockRef(StableBlockIdentity.from_instruction_eas((0x2000,), native_key=key))
    block = model.InventoryBlockObservation(
        1, ref, 0x1000, (0x1000,), (), (), None,
        (_obs(0, 0x1000, 0, 0),),
    )
    with pytest.raises(ValueError):
        _inventory(blocks=(block,))


def test_inventory_tail_control_transfer_requires_transfer_ea() -> None:
    row = _obs(0, 0x1000, 0, 0, InsnKind.GOTO, ControlTransferKind.GOTO)
    with pytest.raises(ValueError):
        model.InventoryBlockObservation(
            1, None, 0x1000, (0x1000,), (), (2,), None, (row,),
        )


def test_inventory_rejects_non_tail_control_transfer() -> None:
    rows = (
        _obs(0, 0x1000, 0, 0, InsnKind.GOTO, ControlTransferKind.GOTO),
        _obs(1, 0x1004, 0, 0),
    )
    with pytest.raises(ValueError):
        model.InventoryBlockObservation(
            1, None, 0x1000, (0x1000, 0x1004), (), (2,), None, rows,
        )


def test_inventory_rejects_foreign_valid_native_identity() -> None:
    key = NativePreanalysisKey("input", "x86", 64, 0, "function", "profile", "sdk")
    ref = NativeBlockRef(StableBlockIdentity.from_instruction_eas((0x2000,), native_key=key))
    instruction = _obs(0, 0x1000, 0, 0)
    block = model.InventoryBlockObservation(1, ref, 0x1000, (0x1000,), (), (), None, (instruction,))
    phase = model.UnflattenAuthorityPhase.PRODUCER_FORECAST
    fingerprint = authority_id("graph")
    digest = semantic_graph_inventory_digest(phase, fingerprint, 3, (block,), (), (), (), (), (), (1,), 1, ())
    with pytest.raises(ValueError):
        model.SemanticGraphInventory(
            phase, fingerprint, 3, (block,), (), (), (), (), (), digest, (1,), 1, (),
        )


def test_inventory_rejects_site_ordinal_against_unique_native_eas() -> None:
    block = model.InventoryBlockObservation(
        1, None, 0x1000, (0x1000,), (), (), None,
        (_obs(0, 0x1000, 1, 0, InsnKind.STORE),),
    )
    forged = model.InventoryEffectSite(1, None, 0x1000, 1, 0x1000, model.EffectSiteKind.STORE, 1, 0)
    with pytest.raises(ValueError):
        _inventory(blocks=(block,), effects=(forged,))


@pytest.mark.parametrize(
    ("phase", "source", "candidate"),
    [
        (model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, 1, 1),
        (model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1),
    ],
)
def test_phase_build_metrics_are_phase_specific(
    phase: model.UnflattenAuthorityPhase, source: int, candidate: int,
) -> None:
    metrics = model.PhaseBuildMetrics(phase, source, candidate, 0.25)
    assert metrics.phase is phase
    for bad in ((True, candidate), (source, True), (-1, candidate), (source, -1)):
        with pytest.raises((TypeError, ValueError)):
            model.PhaseBuildMetrics(phase, bad[0], bad[1], 0.25)
    with pytest.raises((TypeError, ValueError)):
        model.PhaseBuildMetrics(phase, source, candidate, float("nan"))
    with pytest.raises(ValueError):
        model.PhaseBuildMetrics(model.UnflattenAuthorityPhase.PRODUCER_FORECAST, 1, 1, 0.25)
    with pytest.raises((TypeError, ValueError)):
        model.PreparationBuildMetrics(True, True, 0.5)


def test_semantic_phase_metrics_keep_observed_inventory_count_honest() -> None:
    preparation = model.PreparationBuildMetrics(1, 1, 0.5)
    observed_build = model.PhaseBuildMetrics(
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY, 0, 1, 9.25,
    )
    observed = model.SemanticPhaseMetrics(
        preparation, 0, 1, 1, 0,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        observed_build,
    )
    assert observed.build_metrics is observed_build
    assert observed.build_metrics.inventory_ms == 9.25
    with pytest.raises(ValueError):
        model.SemanticPhaseMetrics(
            preparation, 1, 1, 1, 0,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            observed_build,
        )
    corrupted = object.__new__(model.PreparationBuildMetrics)
    object.__setattr__(corrupted, "source_inventory_builds", 1)
    object.__setattr__(corrupted, "candidate_inventory_builds", 1)
    object.__setattr__(corrupted, "inventory_ms", float("nan"))
    with pytest.raises((TypeError, ValueError)):
        model.SemanticPhaseMetrics(corrupted, 0, 1, 1, 0,
                                   model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
                                   observed_build)
    object.__setattr__(observed_build, "inventory_ms", float("nan"))
    with pytest.raises((TypeError, ValueError)):
        model.SemanticPhaseMetrics.__post_init__(observed)
