"""Use-def proposal descendants must remain detached through owner lifetime."""

import pytest

from d810.core.structural_identity import StructuralTable
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import canonical_bytes


def _witness():
    return model.UseDefFragmentWitness(
        "sha256:" + "1" * 64, StorageIdentity(StorageIdentityKind.REGISTER, 5),
        (LogicalBlockRef("session", "block", 2),), "sha256:" + "2" * 64, True, True, 0, (),
    )


def test_use_def_owned_value_detaches_storage_and_owner_reference():
    value = _witness()
    expected = canonical_bytes(value)
    table = StructuralTable()
    ref = proposal_inputs.capture_use_def_witness(table, value)
    object.__setattr__(value.state_identity, "offset", 8)
    object.__setattr__(value.redirect_owner_refs[0], "version", 4)
    assert canonical_bytes(proposal_inputs.materialize_use_def_witness(table, ref)) == expected


def test_use_def_materialization_refuses_shared_enum_value_drift():
    table = StructuralTable()
    ref = proposal_inputs.capture_use_def_witness(table, _witness())
    member = StorageIdentityKind.REGISTER
    original = member.value
    try:
        object.__setattr__(member, "_value_", "changed")
        with pytest.raises((TypeError, ValueError)):
            proposal_inputs.materialize_use_def_witness(table, ref)
    finally:
        object.__setattr__(member, "_value_", original)


def test_use_def_materialization_refuses_shared_enum_name_drift():
    table = StructuralTable()
    ref = proposal_inputs.capture_use_def_witness(table, _witness())
    member = StorageIdentityKind.REGISTER
    original = member.name
    try:
        object.__setattr__(member, "_name_", "changed")
        with pytest.raises((TypeError, ValueError)):
            proposal_inputs.materialize_use_def_witness(table, ref)
    finally:
        object.__setattr__(member, "_name_", original)
