"""Claim representation preserves canonical IDs without carrying runtime authority."""
import pytest
from d810.core.structural_identity import StructuralTable
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import canonical_bytes, validate_canonical_roundtrip
from .test_model import _valid_proposal


def test_route_claim_detaches_subjects_and_omits_runtime_only_references():
    value = _valid_proposal(model)["claims"][0]
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    object.__setattr__(value, "_runtime_refs", object())
    object.__setattr__(value.source_subject, "_runtime_ref", object())
    table = StructuralTable()
    ref = proposal_inputs.capture_route_claim(table, value)
    object.__setattr__(value.source_subject.locator, "anchor_ea", 0x9999)
    restored = proposal_inputs.materialize_route_claim(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored._runtime_refs is None
    assert restored.source_subject._runtime_ref is None
    assert restored.source_subject is not value.source_subject


@pytest.mark.parametrize("target", ("claim", "subject"))
def test_route_claim_reconstruction_checks_supplied_lazy_ids(target):
    value = _valid_proposal(model)["claims"][0]
    record, field = ((value, "claim_id") if target == "claim"
                     else (value.source_subject, "subject_id"))
    object.__setattr__(record, field, "sha256:" + "f" * 64)
    with pytest.raises(ValueError):
        validate_canonical_roundtrip(value, type(value))
    table = StructuralTable()
    ref = proposal_inputs.capture_route_claim(table, value)
    with pytest.raises(ValueError):
        proposal_inputs.materialize_route_claim(table, ref)
