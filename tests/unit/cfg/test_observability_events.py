"""Tests for the cfg observability event API (Phase 2)."""
from __future__ import annotations

import pytest

from d810.core.observability_cfg import (
    BlockLineageDrainRequested,
    CfgProvenanceObserved,
    WatchBlockTransitionObserved,
    diagnostics_enabled,
    observe_cfg_provenance,
    observe_watch_block_transition,
)
from d810.core.observability import (
    SnapshotRef,
    reset_diagnostic_bus,
    subscribe,
)


@pytest.fixture(autouse=True)
def _bus_reset():
    reset_diagnostic_bus()
    yield
    reset_diagnostic_bus()


def test_observe_cfg_provenance_publishes_event():
    seen: list[CfgProvenanceObserved] = []
    subscribe(CfgProvenanceObserved, seen.append)

    observe_cfg_provenance(
        pass_name="cfg_mutations",
        action="REDIRECT_EDGE",
        block_serial=12,
        target_serial=34,
        reason="dispatcher residual",
        extra={"key": 1},
        block_label="blk[12]@0x1000",
        target_label="blk[34]@0x2000",
        maturity_label="MMAT_GLBOPT1",
    )

    assert len(seen) == 1
    ev = seen[0]
    assert ev.pass_name == "cfg_mutations"
    assert ev.action == "REDIRECT_EDGE"
    assert ev.block_serial == 12
    assert ev.target_serial == 34
    assert ev.reason == "dispatcher residual"
    assert ev.extra == {"key": 1}
    assert ev.block_label == "blk[12]@0x1000"
    assert ev.target_label == "blk[34]@0x2000"
    assert ev.maturity_label == "MMAT_GLBOPT1"


def test_observe_cfg_provenance_handles_optional_fields():
    seen: list[CfgProvenanceObserved] = []
    subscribe(CfgProvenanceObserved, seen.append)

    observe_cfg_provenance(
        pass_name="x",
        action="DELETE",
        block_serial=1,
    )

    ev = seen[0]
    assert ev.target_serial is None
    assert ev.reason == ""
    assert ev.extra == {}
    assert ev.block_label is None


def test_observe_watch_block_transition_carries_full_shape():
    seen: list[WatchBlockTransitionObserved] = []
    subscribe(WatchBlockTransitionObserved, seen.append)

    observe_watch_block_transition(
        func_ea=0x401000,
        apply_session_id="apply_1",
        mod_index=7,
        mod_type="RedirectGoto",
        phase="post_apply",
        block_serial=12,
        prev_type_name="BLT_NWAY",
        prev_succs=(13, 14),
        prev_preds=(11,),
        now_type_name="BLT_1WAY",
        now_succs=(13,),
        now_preds=(11,),
    )

    ev = seen[0]
    assert ev.func_ea == 0x401000
    assert ev.apply_session_id == "apply_1"
    assert ev.mod_index == 7
    assert ev.block_serial == 12
    assert ev.prev_succs == (13, 14)
    assert ev.now_succs == (13,)


def test_diagnostics_enabled_reflects_subscribers():
    assert diagnostics_enabled() is False
    subscribe(CfgProvenanceObserved, lambda _: None)
    assert diagnostics_enabled() is True


def test_observe_with_no_subscriber_is_noop():
    observe_cfg_provenance(pass_name="x", action="y", block_serial=0)


def test_block_lineage_drain_requested_event_is_dispatchable():
    """Just verify the event type can be subscribed and emitted.

    The emit happens from ``snapshot_mba`` after the snapshots row is
    created; the cfg.block_lineage subscriber drains its buffered rows
    using the conn + snap_id payload.
    """
    from d810.core.observability import emit as _emit

    seen: list[BlockLineageDrainRequested] = []
    subscribe(BlockLineageDrainRequested, seen.append)
    fake_conn = object()
    _emit(BlockLineageDrainRequested(conn=fake_conn, snapshot_id=42))
    assert seen[0].conn is fake_conn
    assert seen[0].snapshot_id == 42
    assert seen[0].snapshot is None
