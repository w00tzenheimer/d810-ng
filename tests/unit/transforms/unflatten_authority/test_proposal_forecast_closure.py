"""Forecast reconstruction must retain the decoder's derived-ID checks."""

import pytest

from d810.core.structural_identity import StructuralTable
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import canonical_bytes, validate_canonical_roundtrip
from .test_model import _minimal_corridor_forecast, _valid_proposal


def _forecast():
    return _minimal_corridor_forecast(model, model.ProposedUnflattenContract(**_valid_proposal(model)))


def test_forecast_closure_detaches_nodes_and_preserves_boundary_bytes():
    value = _forecast()
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_corridor_forecast(table, value)
    object.__setattr__(value.paths[0].nodes[0], "anchor_ea", 0x7777)
    restored = proposal_inputs.materialize_corridor_forecast(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored.paths[0].nodes[0] is not value.paths[0].nodes[0]


def test_forecast_reconstruction_rederives_supplied_lazy_path_id():
    value = _forecast()
    object.__setattr__(value.paths[0], "path_id", "sha256:" + "f" * 64)
    with pytest.raises(ValueError):
        validate_canonical_roundtrip(value, type(value))
    table = StructuralTable()
    ref = proposal_inputs.capture_corridor_forecast(table, value)
    with pytest.raises(ValueError):
        proposal_inputs.materialize_corridor_forecast(table, ref)


def test_forecast_capture_handles_an_unmaterialized_lazy_identity():
    value = _forecast()
    expected = value.paths[0].path_id
    object.__delattr__(value.paths[0], "path_id")
    table = StructuralTable()
    ref = proposal_inputs.capture_corridor_forecast(table, value)
    assert proposal_inputs.materialize_corridor_forecast(table, ref).paths[0].path_id == expected


@pytest.mark.parametrize("with_feeder", (False, True))
def test_forecast_semantic_exclusion_descendants_preserve_boundary_bytes(with_feeder):
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.transforms.unflatten_authority.ids import authority_id

    base = _forecast()
    source, dispatcher = base.paths[0].nodes
    state = StorageIdentity(StorageIdentityKind.REGISTER, 5)
    feeder = source if with_feeder else None
    content = ("unflatten.corridor-semantic-exclusion.v1", 2, state,
               source, feeder, source, dispatcher)
    exclusion = model.CorridorSemanticExclusion(
        authority_id(content),
        authority_id(("unflatten.corridor-semantic-exclusion-digest.v1", content)),
        2, state, source, feeder, source, dispatcher,
    )
    path = model.CorridorCoveragePath(
        base.paths[0].nodes, source, model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED,
        (exclusion.exclusion_id,),
    )
    values = (base.plan_id, base.function_ea, base.source_native_key,
              base.source_generation, base.dispatcher_ref, base.dispatcher_anchor_ea,
              (path,), (path.path_id,), (), True,
              ((exclusion.exclusion_id, exclusion.digest),), (exclusion,),
              ((exclusion.exclusion_id, (path.path_id,)),))
    value = model.CorridorCoverageForecast(
        authority_id(("unflatten.corridor-coverage-forecast.v1", *values)), *values,
    )
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_corridor_forecast(table, value)
    object.__setattr__(state, "offset", 8)
    restored = proposal_inputs.materialize_corridor_forecast(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored.semantic_exclusions[0].state_identity is not state


def test_forecast_capture_rejects_foreign_scalar_before_lazy_accessor(monkeypatch):
    value = _forecast()
    object.__delattr__(value.paths[0], "path_id")
    object.__setattr__(value.paths[0].nodes[0], "anchor_ea", object())

    def refuse_accessor(self, name):
        pytest.fail("lazy accessor ran before descendant closure")

    monkeypatch.setattr(model.CorridorCoveragePath, "__getattr__", refuse_accessor)
    with pytest.raises(TypeError):
        proposal_inputs.capture_corridor_forecast(StructuralTable(), value)
