"""Tests for the hexrays observability event API (Phase 2)."""
from __future__ import annotations

import pytest

from d810.core.observability import (
    SnapshotRef,
    reset_diagnostic_bus,
    subscribe,
)
from d810.core.observability_models import BlockSnapshot, InstructionSnapshot
from d810.hexrays.observability import (
    CaptureMbaSnapshotRequested,
    diagnostics_enabled,
    request_capture_mba_snapshot,
)


@pytest.fixture(autouse=True)
def _bus_reset():
    reset_diagnostic_bus()
    yield
    reset_diagnostic_bus()


def test_request_capture_returns_none_when_no_subscriber():
    snap = request_capture_mba_snapshot(
        blocks=[],
        label="post_d810",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    assert snap is None


def test_request_capture_returns_snapshot_ref_when_subscribed():
    captured: list[CaptureMbaSnapshotRequested] = []
    subscribe(CaptureMbaSnapshotRequested, captured.append)

    snap = request_capture_mba_snapshot(
        blocks=[],
        label="post_d810",
        func_ea=0x401000,
        maturity="MMAT_GLBOPT1",
        phase="post_d810",
    )
    assert snap is not None
    assert isinstance(snap, SnapshotRef)
    assert snap.func_ea == 0x401000
    assert snap.label == "post_d810"
    assert snap.maturity == "MMAT_GLBOPT1"
    assert snap.phase == "post_d810"
    assert snap.key  # non-empty uuid hex


def test_request_capture_publishes_event_with_blocks_tuple():
    captured: list[CaptureMbaSnapshotRequested] = []
    subscribe(CaptureMbaSnapshotRequested, captured.append)

    blocks = [
        BlockSnapshot(serial=0, block_type=1, type_name="BLT_NWAY", start_ea=0x100),
        BlockSnapshot(serial=1, block_type=1, type_name="BLT_NWAY", start_ea=0x200),
    ]
    request_capture_mba_snapshot(
        blocks=blocks,
        label="lbl",
        func_ea=0x500,
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
    )

    assert len(captured) == 1
    ev = captured[0]
    assert isinstance(ev.blocks, tuple)
    assert ev.blocks[0].serial == 0
    assert ev.blocks[1].serial == 1
    # snapshot key matches the returned ref's identity
    assert ev.snapshot.label == "lbl"


def test_request_capture_unique_snapshot_ref_per_call():
    subscribe(CaptureMbaSnapshotRequested, lambda _: None)
    s1 = request_capture_mba_snapshot(
        blocks=[], label="l", func_ea=1, maturity="M", phase="p",
    )
    s2 = request_capture_mba_snapshot(
        blocks=[], label="l", func_ea=1, maturity="M", phase="p",
    )
    assert s1 is not None and s2 is not None
    assert s1.key != s2.key


def test_diagnostics_enabled_reflects_subscriber():
    assert diagnostics_enabled() is False
    subscribe(CaptureMbaSnapshotRequested, lambda _: None)
    assert diagnostics_enabled() is True


def test_subscriber_receives_block_snapshots_with_full_instruction_payload():
    captured: list[CaptureMbaSnapshotRequested] = []
    subscribe(CaptureMbaSnapshotRequested, captured.append)

    blocks = [
        BlockSnapshot(
            serial=0,
            block_type=1,
            type_name="BLT_NWAY",
            start_ea=0x100,
            instructions=[
                InstructionSnapshot(
                    index=0,
                    ea=0x100,
                    opcode=0x10,
                    opcode_name="m_mov",
                    dest_type="mop_S",
                    dest_stkoff=0x3C,
                    src_l_type="mop_n",
                    src_l_value=0x5FE86821,
                    dstr="state = 0x5FE86821",
                ),
            ],
        ),
    ]
    request_capture_mba_snapshot(
        blocks=blocks, label="x", func_ea=1, maturity="M", phase="p",
    )

    ev = captured[0]
    assert ev.blocks[0].instructions[0].opcode_name == "m_mov"
    assert ev.blocks[0].instructions[0].src_l_value == 0x5FE86821
