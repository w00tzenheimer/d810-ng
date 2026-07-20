"""Portable evidence ownership for one top-level decompilation."""

from __future__ import annotations

from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
    NativePreanalysisSessionState,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


def test_changed_route_evidence_advances_once_and_binds_once() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),), native_key=NATIVE_KEY
    )
    state = NativePreanalysisSessionState()
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x40D348,
        state=0x699BC698,
        handler_identity=handler,
        handler_anchor_ea=0x40EAA7,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )

    assert state.merge_bootstrap_route(route)
    assert state.evidence_generation == 1
    assert not state.merge_bootstrap_route(route)
    assert state.evidence_generation == 1
    assert state.request_controlled_redo()
    assert not state.request_controlled_redo()
    assert state.needs_preopt_binding()
    state.mark_preopt_bound()
    assert not state.needs_preopt_binding()
    assert state.bound_preopt_generation == 1


def test_first_pass_native_evidence_coalesces_until_preopt_binds() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    state = NativePreanalysisSessionState()

    state.mark_evidence_changed()
    assert state.evidence_generation == 1
    assert state.merge_bootstrap_route(
        BootstrapRouteEvidence(
            source_identity=source,
            source_anchor_ea=0x401020,
            state=0x12345678,
            handler_identity=handler,
            handler_anchor_ea=0x401100,
            proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
        )
    )
    assert state.evidence_generation == 1

    assert state.mark_preopt_bound()
    state.mark_evidence_changed()
    assert state.evidence_generation == 2


def test_rebound_bootstrap_route_is_acknowledged_only_after_publication() -> None:
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    handler = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    route = BootstrapRouteEvidence(
        source_identity=source,
        source_anchor_ea=0x401020,
        state=0x12345678,
        handler_identity=handler,
        handler_anchor_ea=0x401100,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    state = NativePreanalysisSessionState()
    assert state.merge_bootstrap_route(route)
    assert state.mark_bootstrap_route_rebound(route)
    assert state.pending_rebound_bootstrap_routes() == (route,)
    state.mark_rebound_bootstrap_routes_published((route,))
    assert state.pending_rebound_bootstrap_routes() == ()
