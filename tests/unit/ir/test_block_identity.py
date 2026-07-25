"""Portable block-identity contract tests."""

from __future__ import annotations

from dataclasses import fields

import d810.ir.block_identity as block_identity
import pytest
from d810.ir.flowgraph import BlockSnapshot, InsnSnapshot
from tests.native_preanalysis import make_native_key


def test_exposes_the_portable_block_identity_contract() -> None:
    """Cross-maturity routing has explicit identity and rebind vocabulary."""
    for name in (
        "NativeEaInterval",
        "NativeEaIntervalSet",
        "StableBlockIdentity",
        "CurrentMbaBlockIdentityBinding",
        "CurrentMbaIdentityBindingSnapshot",
        "MbaBlockHandle",
        "BlockHandleProvenance",
        "RebindStatus",
        "BoundBlock",
        "RebindResult",
        "stable_block_identity_semantic_anchor",
        "stable_block_identities_refine_at_anchor",
        "stable_block_identity_token",
    ):
        assert hasattr(block_identity, name), name


def test_identity_layout_keeps_serial_out_of_durable_identity() -> None:
    """Only the live MBA handle may carry the current serial."""
    assert [field.name for field in fields(block_identity.NativeEaInterval)] == [
        "start_ea",
        "end_ea",
    ]
    assert [field.name for field in fields(block_identity.NativeEaIntervalSet)] == [
        "intervals",
    ]
    assert [field.name for field in fields(block_identity.StableBlockIdentity)] == [
        "native_key",
        "exact_instruction_eas",
        "native_ranges",
    ]
    assert [
        field.name for field in fields(block_identity.CurrentMbaBlockIdentityBinding)
    ] == [
        "stable_identity",
        "live_instruction_eas",
    ]
    assert [
        field.name for field in fields(block_identity.CurrentMbaIdentityBindingSnapshot)
    ] == [
        "instruction_origins",
        "block_bindings",
    ]
    assert [field.name for field in fields(block_identity.MbaBlockHandle)] == [
        "session_id",
        "token",
        "stable_identity",
        "provenance",
    ]
    assert [field.name for field in fields(block_identity.BoundBlock)] == [
        "handle",
        "serial",
        "generation",
        "anchor_ea",
    ]
    assert "serial" not in {
        field.name for field in fields(block_identity.StableBlockIdentity)
    }
    assert "serial" not in {
        field.name for field in fields(block_identity.CurrentMbaBlockIdentityBinding)
    }
    assert "serial" not in {
        field.name for field in fields(block_identity.CurrentMbaIdentityBindingSnapshot)
    }


def test_current_mba_identity_snapshot_ties_full_ranges_to_live_anchors() -> None:
    identity = block_identity.StableBlockIdentity.from_intervals(
        (block_identity.NativeEaInterval(0x40C623, 0x40C696),),
        native_key=make_native_key(),
        exact_instruction_eas=(0x40C64B,),
    )
    binding = block_identity.CurrentMbaBlockIdentityBinding(
        stable_identity=identity,
        live_instruction_eas=frozenset({0xFFFFFFFFFFFFFF01}),
    )

    snapshot = block_identity.CurrentMbaIdentityBindingSnapshot(
        instruction_origins=((0xFFFFFFFFFFFFFF01, 0x40C64B),),
        block_bindings=(binding,),
    )

    assert snapshot.instruction_origins == ((0xFFFFFFFFFFFFFF01, 0x40C64B),)
    assert snapshot.block_bindings == (binding,)


def test_exact_anchor_refinement_matches_split_and_portable_identities() -> None:
    native_key = make_native_key()
    portable = block_identity.StableBlockIdentity.from_intervals(
        (block_identity.NativeEaInterval(0x40A5AB, 0x40A5D0),),
        native_key=native_key,
        exact_instruction_eas=(0x40A5AB,),
    )
    live_split = block_identity.StableBlockIdentity.from_intervals(
        (block_identity.NativeEaInterval(0x40A5AB, 0x40A5AC),),
        native_key=native_key,
        exact_instruction_eas=(0x40A5AB,),
    )
    overlap_only = block_identity.StableBlockIdentity.from_intervals(
        (block_identity.NativeEaInterval(0x40A5A0, 0x40A5B0),),
        native_key=native_key,
        exact_instruction_eas=(0x40A5AB,),
    )
    wrong_native = block_identity.StableBlockIdentity.from_intervals(
        (block_identity.NativeEaInterval(0x40A5AB, 0x40A5AC),),
        native_key=make_native_key(function_rva=0x2000),
        exact_instruction_eas=(0x40A5AB,),
    )

    assert block_identity.stable_block_identities_refine_at_anchor(
        portable,
        live_split,
        0x40A5AB,
    )
    assert block_identity.stable_block_identities_refine_at_anchor(
        live_split,
        portable,
        0x40A5AB,
    )
    assert not block_identity.stable_block_identities_refine_at_anchor(
        portable,
        overlap_only,
        0x40A5AB,
    )
    assert not block_identity.stable_block_identities_refine_at_anchor(
        portable,
        wrong_native,
        0x40A5AB,
    )
    assert not block_identity.stable_block_identities_refine_at_anchor(
        portable,
        live_split,
        0x40A5AC,
    )


def test_identity_contract_exposes_explicit_construction_and_rebind_results() -> None:
    """Callers cannot accidentally construct durable identity from a serial."""
    assert callable(getattr(block_identity.NativeEaIntervalSet, "from_intervals", None))
    assert callable(getattr(block_identity.StableBlockIdentity, "from_intervals", None))
    assert callable(getattr(block_identity.MbaBlockHandle, "native", None))
    assert callable(getattr(block_identity.MbaBlockHandle, "imported_native", None))
    assert callable(getattr(block_identity.MbaBlockHandle, "created_synthetic", None))
    assert callable(getattr(block_identity.MbaBlockHandle, "observed_ephemeral", None))
    assert not hasattr(block_identity.MbaBlockHandle, "synthetic")
    assert callable(getattr(block_identity.RebindResult, "bound", None))


def test_native_identity_is_canonical_and_never_uses_a_block_serial() -> None:
    intervals = block_identity.NativeEaIntervalSet.from_intervals(
        (
            block_identity.NativeEaInterval(0x40EAA7, 0x40EAAB),
            block_identity.NativeEaInterval(0x40D350, 0x40D358),
            block_identity.NativeEaInterval(0x40D348, 0x40D350),
        )
    )

    assert intervals.intervals == (
        block_identity.NativeEaInterval(0x40D348, 0x40D358),
        block_identity.NativeEaInterval(0x40EAA7, 0x40EAAB),
    )
    identity = block_identity.StableBlockIdentity.from_intervals(
        intervals.intervals,
        native_key=make_native_key(),
    )
    assert identity.diagnostic_label() == (
        "input=sha256:test-input-a function-rva=0x1000 exact-ea=[] "
        "native-ea=[0x40D348-0x40D358,0x40EAA7-0x40EAAB]"
    )
    assert not hasattr(identity, "serial")
    with pytest.raises(ValueError, match="requires native ranges"):
        block_identity.StableBlockIdentity(
            native_key=make_native_key(),
            exact_instruction_eas=frozenset(),
            native_ranges=block_identity.NativeEaIntervalSet.from_intervals(()),
        )


def test_rebind_results_keep_serials_only_in_current_bound_blocks() -> None:
    identity = block_identity.StableBlockIdentity.from_intervals(
        (block_identity.NativeEaInterval(0x40D348, 0x40D349),),
        native_key=make_native_key(),
    )
    native = block_identity.MbaBlockHandle.native(
        identity,
        session_id="session-3",
        token="native-17",
    )
    imported = block_identity.MbaBlockHandle.imported_native(
        identity,
        session_id="session-3",
        token="imported-native-18",
    )
    synthetic = block_identity.MbaBlockHandle.observed_ephemeral(
        session_id="session-3",
        token="synthetic-18",
    )
    bound = block_identity.BoundBlock(
        handle=native,
        serial=17,
        generation=3,
        anchor_ea=0x40D348,
    )

    assert block_identity.RebindResult.bound(bound) == block_identity.RebindResult(
        status=block_identity.RebindStatus.BOUND,
        block=bound,
    )
    assert block_identity.RebindResult.stale_generation().status is (
        block_identity.RebindStatus.STALE_GENERATION
    )
    assert synthetic.stable_identity is None
    assert imported.stable_identity == identity
    assert imported.provenance is (block_identity.BlockHandleProvenance.IMPORTED_NATIVE)
    assert synthetic.provenance is (
        block_identity.BlockHandleProvenance.OBSERVED_EPHEMERAL
    )
    with pytest.raises(ValueError, match="must not claim stable identity"):
        block_identity.MbaBlockHandle(
            session_id="session-3",
            token="synthetic-18",
            stable_identity=identity,
            provenance=block_identity.BlockHandleProvenance.CREATED_SYNTHETIC,
        )


def test_identity_serialization_preserves_native_scope_and_exact_ownership() -> None:
    identity = block_identity.StableBlockIdentity.from_intervals(
        (
            block_identity.NativeEaInterval(0x401000, 0x401001),
            block_identity.NativeEaInterval(0x401010, 0x401018),
        ),
        native_key=make_native_key(),
        exact_instruction_eas=(0x401000, 0x401010),
    )

    assert block_identity.StableBlockIdentity.from_dict(identity.to_dict()) == identity


def test_same_native_ranges_from_different_inputs_are_distinct() -> None:
    intervals = (block_identity.NativeEaInterval(0x401000, 0x401001),)

    left = block_identity.StableBlockIdentity.from_intervals(
        intervals,
        native_key=make_native_key(input_identity="sha256:input-left"),
    )
    right = block_identity.StableBlockIdentity.from_intervals(
        intervals,
        native_key=make_native_key(input_identity="sha256:input-right"),
    )

    assert left != right


def test_snapshot_identity_keeps_block_start_as_range_not_exact_instruction() -> None:
    identity = block_identity.stable_block_identity_from_snapshot(
        BlockSnapshot(
            serial=7,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0x401000,
            insn_snapshots=(InsnSnapshot(opcode=0, ea=0x401005, operands=()),),
        ),
        native_key=make_native_key(),
    )

    assert identity is not None
    assert identity.native_ranges.contains(0x401000)
    assert identity.native_ranges.contains(0x401005)
    assert identity.exact_instruction_eas == frozenset({0x401005})


def test_snapshot_identity_uses_native_origins_not_live_fictitious_eas() -> None:
    live_predicate_ea = 0xF1C00018
    identity = block_identity.stable_block_identity_from_snapshot(
        BlockSnapshot(
            serial=7,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0x401000,
            native_start_ea=0x401000,
            insn_snapshots=(
                InsnSnapshot(
                    opcode=0,
                    ea=live_predicate_ea,
                    native_ea=0x401020,
                    operands=(),
                ),
            ),
        ),
        native_key=make_native_key(),
    )

    assert identity is not None
    assert identity.native_ranges.contains(0x401000)
    assert identity.native_ranges.contains(0x401020)
    assert not identity.native_ranges.contains(live_predicate_ea)
    assert identity.exact_instruction_eas == frozenset({0x401020})


def test_stable_identity_exposes_one_serial_free_anchor_and_token() -> None:
    identity = block_identity.StableBlockIdentity.from_intervals(
        (
            block_identity.NativeEaInterval(0x401000, 0x401001),
            block_identity.NativeEaInterval(0x401005, 0x401007),
        ),
        native_key=make_native_key(),
        exact_instruction_eas=(0x401005, 0x401006),
    )

    assert block_identity.stable_block_identity_semantic_anchor(identity) == 0x401005
    assert block_identity.stable_block_identity_token(identity) == (
        "0x401000-0x401001,0x401005-0x401007;exact=0x401005,0x401006"
    )
