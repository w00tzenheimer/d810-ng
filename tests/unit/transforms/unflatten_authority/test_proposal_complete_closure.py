"""Whole proposal reconstruction owns every encoded field, never runtime joins."""
import pytest
from d810.core.structural_identity import StructuralTable
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import canonical_bytes, validate_canonical_roundtrip
from .test_model import _valid_proposal


def test_complete_proposal_detaches_route_and_nonroute_descendants_without_binding():
    value = model.ProposedUnflattenContract(**_valid_proposal(model))
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_proposal(table, value)
    object.__setattr__(value.source_identity_catalog.blocks[0], "anchor_ea", 0x9999)
    object.__setattr__(value.route_evidence.route_proofs[0].destinations[0], "target_anchor_ea", 0x8888)
    restored = proposal_inputs.materialize_proposal(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored.route_evidence.route_binding is None
    assert restored.route_evidence.runtime_identity is None


def test_complete_proposal_constructor_rejects_tampered_group_identity():
    value = model.ProposedUnflattenContract(**_valid_proposal(model))
    object.__setattr__(value.route_evidence, "atomic_group_id", "sha256:" + "f" * 64)
    with pytest.raises(ValueError):
        validate_canonical_roundtrip(value, type(value))
    table = StructuralTable()
    ref = proposal_inputs.capture_proposal(table, value)
    with pytest.raises(ValueError):
        proposal_inputs.materialize_proposal(table, ref)
