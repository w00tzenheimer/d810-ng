"""Proposal input handles own values; they never certify a proposal."""

import pytest

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.structural_identity import StructuralIdentityError, StructuralTable
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import canonical_bytes


def _catalog():
    key = NativePreanalysisKey("input", "metapc", 64, 1, "function", "profile", "sdk")
    return model.SourceIdentityCatalog(
        key, 3,
        (model.SourceBlockIdentityWitness(LogicalBlockRef("session", "block", 2),
                                          0x1000, (0x1000,)),),
    )


def test_source_catalog_capture_detaches_every_public_descendant():
    from d810.transforms.unflatten_authority import proposal_inputs

    value = _catalog()
    expected = canonical_bytes(value)
    table = StructuralTable()
    ref = proposal_inputs.capture_source_catalog(table, value)
    object.__setattr__(value.blocks[0].block_ref, "version", 9)
    object.__setattr__(value.native_key, "function_fingerprint", "changed")
    object.__setattr__(value.blocks[0], "native_instruction_eas", (0x1000, 0x1001))
    restored = proposal_inputs.materialize_source_catalog(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored is not value
    assert restored.blocks[0] is not value.blocks[0]
    assert restored.blocks[0].block_ref is not value.blocks[0].block_ref
    assert restored.native_key is not value.native_key
    assert proposal_inputs.capture_source_catalog(table, value) != ref


def test_source_catalog_capture_refuses_callback_descendants_before_protocols():
    from d810.transforms.unflatten_authority import proposal_inputs

    class CallbackInt(int):
        def __int__(self):
            pytest.fail("foreign scalar callback ran during capture")

    value = _catalog()
    object.__setattr__(value.blocks[0].block_ref, "version", CallbackInt(2))
    with pytest.raises((TypeError, ValueError)):
        proposal_inputs.capture_source_catalog(StructuralTable(), value)


def test_source_catalog_handles_cannot_outlive_or_cross_their_owner():
    from d810.transforms.unflatten_authority import proposal_inputs

    table = StructuralTable()
    ref = proposal_inputs.capture_source_catalog(table, _catalog())
    with pytest.raises(StructuralIdentityError):
        proposal_inputs.materialize_source_catalog(StructuralTable(), ref)
    table.close()
    with pytest.raises(StructuralIdentityError):
        proposal_inputs.materialize_source_catalog(table, ref)


def test_source_catalog_native_identity_closure_preserves_canonical_bytes():
    from d810.ir.block_identity import (
        NativeBlockRef, NativeEaInterval, NativeEaIntervalSet, StableBlockIdentity,
    )
    from d810.transforms.unflatten_authority import proposal_inputs

    key = _catalog().native_key
    ranges = NativeEaIntervalSet((NativeEaInterval(0x1000, 0x1010),))
    identity = StableBlockIdentity(key, frozenset((0x1000, 0x1004)), ranges)
    value = model.SourceIdentityCatalog(
        key, 3,
        (model.SourceBlockIdentityWitness(NativeBlockRef(identity), 0x1000,
                                          (0x1000, 0x1004)),),
    )
    expected = canonical_bytes(value)
    table = StructuralTable()
    ref = proposal_inputs.capture_source_catalog(table, value)
    object.__setattr__(ranges.intervals[0], "end_ea", 0x1008)
    object.__setattr__(identity, "exact_instruction_eas", frozenset((0x1000,)))
    restored = proposal_inputs.materialize_source_catalog(table, ref)
    assert canonical_bytes(restored) == expected
    assert restored.blocks[0].block_ref.identity.native_ranges is not ranges


def test_source_catalog_capture_rejects_cycle_and_schema_growth(monkeypatch):
    from d810.transforms.unflatten_authority import proposal_inputs

    value = _catalog()
    object.__setattr__(value, "blocks", (value,))
    with pytest.raises(ValueError, match="cycle"):
        proposal_inputs.capture_source_catalog(StructuralTable(), value)
    monkeypatch.setattr(proposal_inputs, "fields", lambda kind: ())
    with pytest.raises(TypeError, match="schema drift"):
        proposal_inputs.capture_source_catalog(StructuralTable(), _catalog())


def test_source_catalog_materialization_still_runs_semantic_constructors():
    from d810.transforms.unflatten_authority import proposal_inputs

    value = _catalog()
    object.__setattr__(value, "generation", -1)
    table = StructuralTable()
    ref = proposal_inputs.capture_source_catalog(table, value)
    # Representability is not proposal validity. Existing constructors refuse it.
    with pytest.raises(ValueError):
        proposal_inputs.materialize_source_catalog(table, ref)


@pytest.mark.parametrize("at_root", (True, False))
def test_source_catalog_materialization_rejects_width_outside_schema(at_root):
    from d810.core.structural_identity import StructuralNodeKind as Kind
    from d810.transforms.unflatten_authority import proposal_inputs

    table = StructuralTable()
    ref = proposal_inputs.capture_source_catalog(table, _catalog())
    node = table.resolve(ref, Kind.SUBJECT)
    if at_root:
        invalid = table.intern(Kind.SUBJECT, 64, node.payload, node.children)
    else:
        generation = table.resolve(node.children[1], Kind.VALUE)
        changed = table.intern(Kind.VALUE, 64, generation.payload, ())
        invalid = table.intern(Kind.SUBJECT, None, node.payload,
                               (node.children[0], changed, node.children[2]))
    with pytest.raises(StructuralIdentityError):
        proposal_inputs.materialize_source_catalog(table, invalid)


def test_source_scalar_materialization_rejects_unadmitted_bytes():
    from d810.core.structural_identity import StructuralNodeKind as Kind
    from d810.transforms.unflatten_authority import proposal_inputs

    table = StructuralTable()
    ref = table.intern(Kind.VALUE, None, (b"foreign",), ())
    with pytest.raises(StructuralIdentityError):
        proposal_inputs._materialize(table, ref)
