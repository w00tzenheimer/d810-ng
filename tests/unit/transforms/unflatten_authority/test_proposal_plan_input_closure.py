"""Owned plan input values preserve logical and native descendant state."""

import pytest

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.structural_identity import StructuralTable
from d810.ir.block_identity import (
    NativeBlockRef, NativeEaInterval, NativeEaIntervalSet, StableBlockIdentity,
)
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.ids import canonical_bytes


def _inputs():
    key = NativePreanalysisKey("input", "metapc", 64, 1, "function", "profile", "sdk")
    native = NativeBlockRef(StableBlockIdentity(
        key, frozenset((0x1000,)),
        NativeEaIntervalSet((NativeEaInterval(0x1000, 0x1010),)),
    ))
    dispatcher = LogicalBlockRef("session", "dispatcher", 2)
    return model.UnflattenPlanInputCatalog(
        model.UnflattenPlanShape.EXACT_EFFECT_ONLY,
        LogicalBlockRef("session", "entry", 2), dispatcher, (dispatcher,),
        (model.AuthoritativeHandlerInput(native, 0x1000, (1, 2)),),
        StorageIdentity(StorageIdentityKind.REGISTER, 5),
    )


def test_plan_inputs_detach_handlers_logical_refs_and_native_key():
    value = _inputs()
    expected = canonical_bytes(value)
    table = StructuralTable()
    ref = proposal_inputs.capture_plan_inputs(table, value)
    object.__setattr__(value.dispatcher_entry_ref, "version", 9)
    object.__setattr__(value.authoritative_handlers[0], "normalized_states", (3,))
    object.__setattr__(value.authoritative_handlers[0].block_ref.identity.native_key,
                       "function_fingerprint", "changed")
    assert canonical_bytes(proposal_inputs.materialize_plan_inputs(table, ref)) == expected


@pytest.mark.parametrize("attribute", ("_name_", "_value_"))
def test_plan_input_read_refuses_shared_shape_enum_drift(attribute):
    table = StructuralTable()
    ref = proposal_inputs.capture_plan_inputs(table, _inputs())
    member = model.UnflattenPlanShape.EXACT_EFFECT_ONLY
    original = object.__getattribute__(member, attribute)
    try:
        object.__setattr__(member, attribute, "changed")
        with pytest.raises((TypeError, ValueError)):
            proposal_inputs.materialize_plan_inputs(table, ref)
    finally:
        object.__setattr__(member, attribute, original)
