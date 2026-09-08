"""Proposal retirement and entry records retain constructor-owned identities."""

import pytest

from d810.core.structural_identity import StructuralTable
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import canonical_bytes, validate_canonical_roundtrip
from .test_model import _retirement_catalog
from .test_entry_liveness_corridor_immutability import entry_records


def _retirement():
    return _retirement_catalog(model, (LogicalBlockRef("session", "member", 2),), (0x1000,))


def test_retirement_catalog_detaches_member_and_candidate_values():
    value = _retirement()
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_retirement_catalog(table, value)
    object.__setattr__(value.plan_members[0].block_ref, "version", 9)
    object.__setattr__(value.candidates[0], "role", "changed")
    assert canonical_bytes(proposal_inputs.materialize_retirement_catalog(table, ref)) == expected


def test_retirement_candidate_identity_is_rechecked_by_constructor():
    value = _retirement()
    object.__setattr__(value.candidates[0], "candidate_id", "sha256:" + "f" * 64)
    with pytest.raises(ValueError):
        validate_canonical_roundtrip(value, type(value))
    table = StructuralTable()
    ref = proposal_inputs.capture_retirement_catalog(table, value)
    with pytest.raises(ValueError):
        proposal_inputs.materialize_retirement_catalog(table, ref)


def test_entry_allowance_closure_keeps_exact_boundary_bytes(entry_records):
    value = entry_records[model.EntryEndpointLivenessAllowance]
    expected = canonical_bytes(validate_canonical_roundtrip(value, type(value)))
    table = StructuralTable()
    ref = proposal_inputs.capture_entry_allowance(table, value)
    object.__setattr__(value, "delivery_path_edges", ((99, 100),))
    assert canonical_bytes(proposal_inputs.materialize_entry_allowance(table, ref)) == expected


def test_entry_allowance_mutable_edge_descendant_is_not_admitted(entry_records):
    value = entry_records[model.EntryEndpointLivenessAllowance]
    object.__setattr__(value, "delivery_path_edges", ([1, 2],))
    with pytest.raises(TypeError):
        proposal_inputs.capture_entry_allowance(StructuralTable(), value)
