"""Default-gap forecast closure retains exact path and seed correspondence."""

import pytest

from d810.core.structural_identity import StructuralIdentityError, StructuralTable
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import canonical_bytes, validate_canonical_roundtrip
from .test_model import _default_gap_wrapper
from .test_proposal_forecast_closure import _forecast


def test_default_gap_closure_detaches_seed_and_path_descendants():
    value, exclusion, path = _default_gap_wrapper(model, _forecast())
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_default_gap_forecast(table, value)
    object.__setattr__(exclusion.initial_state_seeds[0], "normalized_state", 7)
    object.__setattr__(path.nodes[0], "anchor_ea", 0x7777)
    restored = proposal_inputs.materialize_default_gap_forecast(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored.exclusions[0].initial_state_seeds[0] is not exclusion.initial_state_seeds[0]
    with pytest.raises(StructuralIdentityError):
        proposal_inputs.materialize_corridor_forecast(table, ref)


def test_default_gap_supplied_path_identity_still_requires_constructor_validation():
    value, _, path = _default_gap_wrapper(model, _forecast())
    object.__setattr__(path, "path_id", "sha256:" + "f" * 64)
    with pytest.raises(ValueError):
        validate_canonical_roundtrip(value, type(value))
    table = StructuralTable()
    ref = proposal_inputs.capture_default_gap_forecast(table, value)
    with pytest.raises(ValueError):
        proposal_inputs.materialize_default_gap_forecast(table, ref)
