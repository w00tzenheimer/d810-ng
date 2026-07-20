"""Portable block-identity contract tests."""
from __future__ import annotations

from dataclasses import fields

import d810.ir.block_identity as block_identity
import pytest


def test_exposes_the_portable_block_identity_contract() -> None:
    """Cross-maturity routing has explicit identity and rebind vocabulary."""
    for name in (
        "NativeEaInterval",
        "NativeEaIntervalSet",
        "StableBlockIdentity",
        "MbaBlockHandle",
        "BlockHandleProvenance",
        "RebindStatus",
        "BoundBlock",
        "RebindResult",
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
        "native_eas",
    ]
    assert [field.name for field in fields(block_identity.MbaBlockHandle)] == [
        "session_id",
        "token",
        "identity",
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


def test_identity_contract_exposes_explicit_construction_and_rebind_results() -> None:
    """Callers cannot accidentally construct durable identity from a serial."""
    assert callable(
        getattr(block_identity.NativeEaIntervalSet, "from_intervals", None)
    )
    assert callable(
        getattr(block_identity.StableBlockIdentity, "from_intervals", None)
    )
    assert callable(getattr(block_identity.MbaBlockHandle, "native", None))
    assert callable(getattr(block_identity.MbaBlockHandle, "imported_native", None))
    assert callable(getattr(block_identity.MbaBlockHandle, "synthetic", None))
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
    identity = block_identity.StableBlockIdentity.from_intervals(intervals.intervals)
    assert identity.diagnostic_label() == (
        "native-ea=[0x40D348-0x40D358,0x40EAA7-0x40EAAB]"
    )
    assert not hasattr(identity, "serial")
    with pytest.raises(ValueError, match="requires at least one native EA"):
        block_identity.StableBlockIdentity(
            block_identity.NativeEaIntervalSet.from_intervals(())
        )


def test_rebind_results_keep_serials_only_in_current_bound_blocks() -> None:
    identity = block_identity.StableBlockIdentity.from_intervals(
        (block_identity.NativeEaInterval(0x40D348, 0x40D349),)
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
    synthetic = block_identity.MbaBlockHandle.synthetic(
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
    assert synthetic.identity is None
    assert imported.identity == identity
    assert imported.provenance is (
        block_identity.BlockHandleProvenance.IMPORTED_NATIVE
    )
    assert synthetic.provenance is block_identity.BlockHandleProvenance.SYNTHETIC
    with pytest.raises(ValueError, match="must not claim stable identity"):
        block_identity.MbaBlockHandle(
            session_id="session-3",
            token="synthetic-18",
            identity=identity,
            provenance=block_identity.BlockHandleProvenance.SYNTHETIC,
        )
