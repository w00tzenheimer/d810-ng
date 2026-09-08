"""Complete canonical proof terms include IDs and encoded enum state."""
import pytest
from d810.core.structural_identity import StructuralTable
from d810.analyses.control_flow import semantic_route_evidence as routes
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import canonical_bytes, validate_canonical_roundtrip
from .test_model import _canonical_evidence


def test_complete_route_proof_retains_ids_and_detaches_public_destinations():
    value = _canonical_evidence(model)[0].route_proofs[0]
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = routes.capture_canonical_route_proof(table, value)
    object.__setattr__(value.destinations[0], "target_anchor_ea", 0x9999)
    restored = routes.materialize_canonical_route_proof(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored.proof_id == value.proof_id
    assert restored.atomic_group_id == value.atomic_group_id
    assert restored.destinations[0] is not value.destinations[0]


@pytest.mark.parametrize("field", ("_name_", "_value_"))
def test_complete_route_proof_refuses_enum_state_drift(field):
    value = _canonical_evidence(model)[0].route_proofs[0]
    table = StructuralTable()
    ref = routes.capture_canonical_route_proof(table, value)
    enum = value.proof_kind
    original = object.__getattribute__(enum, field)
    try:
        object.__setattr__(enum, field, "changed")
        with pytest.raises(ValueError):
            routes.materialize_canonical_route_proof(table, ref)
    finally:
        object.__setattr__(enum, field, original)


def test_canonical_route_proxy_owns_exact_dict_values():
    from types import MappingProxyType
    values = {"a": (1, 2)}
    table = StructuralTable()
    ref = routes._capture_route_descendant(table, MappingProxyType(values), set(), canonical=True)
    values["a"] = (3,)
    restored = routes._read_owned_route_descendant(
        table, ref, routes._construct_owned_route_record, canonical=True)
    assert restored == {"a": (1, 2)}


def test_canonical_route_rejects_foreign_proxy_before_callbacks():
    from collections.abc import Mapping
    from types import MappingProxyType
    class Foreign(Mapping):
        def __getitem__(self, key):
            pytest.fail("foreign mapping callback")
        def __iter__(self):
            pytest.fail("foreign mapping callback")
        def __len__(self):
            pytest.fail("foreign mapping callback")
    with pytest.raises(TypeError, match="exact dict"):
        routes._capture_route_descendant(StructuralTable(), MappingProxyType(Foreign()), set(), canonical=True)


def test_canonical_physical_proof_detaches_nested_instruction_attributes():
    from tests.unit.analyses.control_flow.test_route_structural_identity import _physical_proof_with_attrs
    aliases = [1, {"value": 2}]
    value = _physical_proof_with_attrs({"custom": aliases})
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = routes.capture_canonical_route_proof(table, value)
    aliases[1]["value"] = 3
    restored = routes.materialize_canonical_route_proof(table, ref)
    assert canonical_bytes(restored) == expected


def test_canonical_proof_capture_refuses_foreign_nested_proxy_before_callback():
    from collections.abc import Mapping
    from types import MappingProxyType
    from tests.unit.analyses.control_flow.test_route_structural_identity import _physical_proof_with_attrs
    value = _physical_proof_with_attrs({"custom": 1})
    class Foreign(Mapping):
        def __getitem__(self, key):
            pytest.fail("foreign mapping callback")
        def __iter__(self):
            pytest.fail("foreign mapping callback")
        def __len__(self):
            pytest.fail("foreign mapping callback")
    object.__setattr__(value.state_write.physical_state_write.source_instruction,
                       "opcode_attrs", MappingProxyType(Foreign()))
    with pytest.raises(TypeError, match="exact dict"):
        routes.capture_canonical_route_proof(StructuralTable(), value)
