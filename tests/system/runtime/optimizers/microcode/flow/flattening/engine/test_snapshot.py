"""Unit tests for shared engine snapshot types."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening import engine
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
    StateModelSummary,
)
from d810.optimizers.microcode.flow.flattening.hodur import snapshot as hodur_snapshot


class _StateMachine:
    state_constants = {1, 2}
    handlers = {1: object()}
    transitions = {(1, 2), (2, 3)}


def test_engine_package_re_exports_snapshot_types() -> None:
    assert engine.AnalysisSnapshot is AnalysisSnapshot
    assert engine.ReachabilityInfo is ReachabilityInfo
    assert engine.StateModelSummary is StateModelSummary


def test_hodur_snapshot_shim_points_to_engine_types() -> None:
    assert hodur_snapshot.AnalysisSnapshot is AnalysisSnapshot
    assert hodur_snapshot.ReachabilityInfo is ReachabilityInfo


def test_reachability_info_coverage() -> None:
    info = ReachabilityInfo(
        entry_serial=0,
        reachable_blocks=frozenset({0, 1, 2}),
        total_blocks=4,
    )
    assert info.coverage == 0.75


def test_analysis_snapshot_convenience_properties() -> None:
    snapshot = AnalysisSnapshot(
        mba=object(),
        state_machine=_StateMachine(),
        resolved_transitions=frozenset({(1, 2)}),
    )

    assert snapshot.state_constants == {1, 2}
    assert snapshot.handler_count == 1
    assert snapshot.transition_count == 2
    assert snapshot.unresolved_transition_count == 1


def test_analysis_snapshot_supports_generic_state_summary_without_hodur_shape() -> None:
    snapshot = AnalysisSnapshot(
        mba=object(),
        state_summary=StateModelSummary(
            state_constants=frozenset({7, 9}),
            handler_count=4,
            transition_count=6,
        ),
        resolved_transitions=frozenset({(1, 2), (2, 3)}),
    )

    assert snapshot.state_constants == {7, 9}
    assert snapshot.handler_count == 4
    assert snapshot.transition_count == 6
    assert snapshot.unresolved_transition_count == 4
