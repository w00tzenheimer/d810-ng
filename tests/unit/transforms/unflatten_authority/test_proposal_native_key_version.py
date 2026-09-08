"""Native key wire version is a virtual canonical field, not a dataclass slot."""
import pytest
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.structural_identity import StructuralTable
from d810.analyses.control_flow import semantic_route_evidence as routes
from d810.transforms.unflatten_authority import model, proposal_inputs
from .test_model import _valid_proposal


@pytest.mark.parametrize("family", ("catalog", "route"))
def test_canonical_native_key_reconstruction_refuses_schema_version_drift(family):
    value = _valid_proposal(model)
    table = StructuralTable()
    if family == "catalog":
        ref = proposal_inputs.capture_source_catalog(table, value["source_identity_catalog"])
        restore = proposal_inputs.materialize_source_catalog
    else:
        ref = routes.capture_canonical_route_proof(table, value["route_evidence"].route_proofs[0])
        restore = routes.materialize_canonical_route_proof
    original = NativePreanalysisKey.SCHEMA_VERSION
    try:
        NativePreanalysisKey.SCHEMA_VERSION = original + 1
        with pytest.raises(ValueError):
            restore(table, ref)
    finally:
        NativePreanalysisKey.SCHEMA_VERSION = original


def test_explicit_proposal_and_route_field_manifests_cover_exact_codec_fields():
    from d810.transforms.unflatten_authority import ids
    ids._ensure_registries()
    for record_type, names in proposal_inputs._SOURCE_FIELDS.items():
        expected = ids._RECORD_FIELDS.get(record_type, ids._EXTERNAL_FIELDS.get(record_type))
        assert names == expected, record_type.__name__
    for record_type, names in routes._ROUTE_STRUCTURAL_FIELDS.items():
        if record_type is NativePreanalysisKey:
            names = ("schema_version", *names)
        expected = ids._RECORD_FIELDS.get(record_type, ids._EXTERNAL_FIELDS.get(record_type))
        if record_type is routes.InstructionUseRef:
            # Stable route terms include this IR value; canonical mode refuses it.
            assert expected is None
        else:
            assert names == expected, record_type.__name__


@pytest.mark.parametrize("value", (routes.InstructionUseRef(None), routes.InstructionUseKind.READ, {1, 2}))
def test_canonical_route_refuses_stable_only_nonwire_values(value):
    from d810.transforms.unflatten_authority.ids import canonical_bytes
    with pytest.raises(TypeError):
        canonical_bytes(value)
    with pytest.raises(TypeError):
        routes._capture_route_descendant(StructuralTable(), value, set(), canonical=True)


@pytest.mark.parametrize("value", (routes.InstructionUseRef(None), routes.InstructionUseKind.READ, {1, 2}))
def test_canonical_route_read_refuses_stable_only_terms(value):
    table = StructuralTable()
    ref = routes._capture_route_descendant(table, value, set())
    with pytest.raises(ValueError):
        routes._read_owned_route_descendant(table, ref, routes._construct_owned_route_record, canonical=True)
