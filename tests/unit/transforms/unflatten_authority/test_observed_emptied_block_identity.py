"""Observed identity of a native block whose body was legitimately removed.

The post-observation contract compares one plan-time catalog identity against
one post-realize observation.  Between those two measurement points a block
can be renumbered (an inserted block shifts every later serial) and its body
can be removed outright -- a proven fake jump folded away leaves the physical
block in place with no surviving microinstruction.  Neither transformation
changes which native block the row denotes, so neither may be reported as a
native-origin identity failure.
"""

from __future__ import annotations

import pytest

from d810.transforms.cfg_transaction import PlanBlockRef
from d810.transforms.unflatten_authority import bind, model, transaction_api
from d810.transforms.unflatten_authority.ids import (
    authority_id,
    semantic_graph_inventory_digest,
)

from .test_bind import _physical_native_anchor_fixture


def test_emptied_physical_anchor_block_keeps_its_native_identity() -> None:
    """A renumbered block folded empty is still its own catalog identity."""

    catalog, ref, subject = _physical_native_anchor_fixture(
        anchor_ea=0x1000, exact_instruction_eas=(0x1010,),
    )

    assert model._phase_native_origin_subset_preserves_anchor(
        ref, 0x1000, (), (0x1010,),
    )

    # The source block was serial 17; an inserted block renumbered it to 18.
    (accepted,) = bind.bind_projected_subjects(
        (subject,), catalog=catalog,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        graph_fingerprint=authority_id("emptied-observed"),
        generation=catalog.generation,
        serial_by_ref={ref: 18},
        native_instruction_eas_by_ref={ref: ()},
    )

    assert accepted.status is model.SubjectBindingStatus.UNIQUE
    assert accepted.serial == 18
    # The binding carries the observed origin set, so the inventory row and
    # its binding still agree after the body was folded away.
    assert accepted.native_instruction_eas == ()


def test_prefix_dce_keeps_identity_when_physical_block_start_survives() -> None:
    """Removing a proved-dead head instruction does not move the block."""

    catalog, ref, subject = _physical_native_anchor_fixture(
        anchor_ea=0x1000,
        exact_instruction_eas=(0x1000, 0x1004, 0x1008),
    )
    observed_origins = (0x1004, 0x1008)

    assert not model._phase_native_origin_subset_preserves_anchor(
        ref,
        0x1000,
        observed_origins,
        (0x1000, 0x1004, 0x1008),
    )
    assert model._phase_native_origin_subset_preserves_anchor(
        ref,
        0x1000,
        observed_origins,
        (0x1000, 0x1004, 0x1008),
        observed_graph_start_ea=0x1000,
    )

    (accepted,) = bind.bind_projected_subjects(
        (subject,),
        catalog=catalog,
        phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        graph_fingerprint=authority_id("prefix-dce-observed"),
        generation=catalog.generation,
        serial_by_ref={ref: 18},
        native_instruction_eas_by_ref={ref: observed_origins},
        graph_start_eas_by_ref={ref: 0x1000},
        anchor_loss_owner_refs=frozenset((ref,)),
    )

    assert accepted.status is model.SubjectBindingStatus.UNIQUE
    assert accepted.serial == 18
    assert accepted.native_instruction_eas == observed_origins


def test_observed_inventory_accepts_an_emptied_native_block_row() -> None:
    """The inventory row validator owns the same identity question."""

    catalog, ref, subject = _physical_native_anchor_fixture(
        anchor_ea=0x1000, exact_instruction_eas=(0x1010,),
    )
    phase = model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    fingerprint = authority_id("emptied-observed-inventory")
    row = model.InventoryBlockObservation(
        18, ref, 0x1000, (), (), (19,), None, (),
        block_kind=model.BlockKind.ONE_WAY, graph_start_ea=0x1000,
    )
    successor = model.InventoryBlockObservation(
        19, PlanBlockRef("emptied", "tail"), 0x1010, (0x1010,), (18,), (), None,
        (
            model.InventoryInstructionObservation(
                0, 0x1010, 1, 0, model.InsnKind.NOP, None, False, None,
                raw_opcode=1,
            ),
        ),
        block_kind=model.BlockKind.ZERO_WAY, graph_start_ea=0x1010,
        tail_opcode=1, raw_tail_opcode=1, tail_kind=model.InsnKind.NOP,
    )
    blocks = (row, successor)
    subjects = (subject,)
    bindings = (
        model.PhaseSubjectBinding(
            subject, phase, ref, fingerprint, catalog.generation,
            model.SubjectBindingStatus.UNIQUE, 18, 0x1000, (),
            subject.role,
        ),
    )
    closure = (18, 19)
    topology = (
        model.InventoryTopologyIncidence(
            model.TopologyIncidenceKind.PREDECESSOR, 19, 18, None,
        ),
        model.InventoryTopologyIncidence(
            model.TopologyIncidenceKind.SUCCESSOR, 18, 19, None,
        ),
    )
    digest = semantic_graph_inventory_digest(
        phase, fingerprint, catalog.generation, blocks, subjects, bindings,
        (), (), topology, closure, 18, (), 0,
    )
    inventory = model.SemanticGraphInventory(
        phase, fingerprint, catalog.generation, blocks, subjects, bindings,
        (), (), topology, digest, closure, 18, (), 0,
    )

    assert inventory.blocks[0].native_instruction_eas == ()


def test_untouched_native_block_with_a_foreign_origin_is_still_rejected() -> None:
    """Identity loss is only forgiven for a body that is gone, not replaced."""

    catalog, ref, subject = _physical_native_anchor_fixture(
        anchor_ea=0x1000, exact_instruction_eas=(0x1010,),
    )

    assert not model._phase_native_origin_subset_preserves_anchor(
        ref, 0x1000, (0x1014,), (0x1010,),
    )

    with pytest.raises(ValueError, match="native identity instruction EAs") as error:
        bind.bind_projected_subjects(
            (subject,), catalog=catalog,
            phase=model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            graph_fingerprint=authority_id("foreign-origin-observed"),
            generation=catalog.generation,
            serial_by_ref={ref: 18},
            native_instruction_eas_by_ref={ref: (0x1014,)},
        )

    message = str(error.value)
    assert "blk18@0x1000 supplied=(0x1014) expected=(0x1010)" in message
    assert "NativeBlockRef(" not in message


def test_live_binding_rejection_names_the_failed_stage_and_cause() -> None:
    """A rejecting verdict must say what it rejected, not just ``failed=()``."""

    verdict = transaction_api._observed_live_binding_failure(
        "observed_inventory",
        ValueError(
            "native identity instruction EAs do not exactly match catalog "
            "blk18@0x1000 supplied=(0x1014) expected=(0x1010)"
        ),
    )

    assert verdict.accepted is False
    assert verdict.reason is model.UnflattenAuthorityReason.LIVE_BINDING_FAILED
    assert verdict.failed_obligations == ()
    assert verdict.rejection_detail is not None
    assert "stage=observed_inventory" in verdict.rejection_detail
    assert "ValueError" in verdict.rejection_detail
    assert "blk18@0x1000" in verdict.rejection_detail
    assert len(verdict.rejection_detail) <= 640
