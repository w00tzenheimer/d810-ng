"""Consumer-demand contract for avoiding unused portable graph lifts."""

from __future__ import annotations

from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.manager.decompilation_lifecycle import (
    DecompilationLifecycleCoordinator,
    FlowgraphSnapshotPayload,
)

from tests.native_preanalysis import make_native_key


class _DemandRuntime:
    def __init__(self, demand: bool) -> None:
        self.demand = demand
        self.attachments: list[tuple[int, object, object]] = []

    def needs_flowgraph(self, *, func_ea, provider_phase) -> bool:
        del func_ea, provider_phase
        return self.demand

    def attach_flowgraph_snapshot(self, *, func_ea, provider_phase, snapshot) -> None:
        self.attachments.append((func_ea, provider_phase, snapshot))


def _phase() -> ProviderPhaseSnapshot:
    return ProviderPhaseSnapshot(
        provider_name="hexrays_microcode",
        provider_level=14,
        friendly_provider_level="MMAT_GLBOPT1",
    )


def _coordinator(runtime) -> DecompilationLifecycleCoordinator:
    return DecompilationLifecycleCoordinator(
        preanalysis_runtime=runtime,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=lambda _ea: make_native_key(),
    )


def test_coordinator_reports_runtime_graph_demand() -> None:
    assert _coordinator(_DemandRuntime(True)).flowgraph_required(
        func_ea=0x401000,
        provider_phase=_phase(),
    )
    assert not _coordinator(_DemandRuntime(False)).flowgraph_required(
        func_ea=0x401000,
        provider_phase=_phase(),
    )


def test_unknown_runtime_demand_fails_closed() -> None:
    assert _coordinator(object()).flowgraph_required(
        func_ea=0x401000,
        provider_phase=_phase(),
    )


def test_snapshot_only_capture_does_not_require_a_graph() -> None:
    runtime = _DemandRuntime(False)
    coordinator = _coordinator(runtime)
    snapshot = object()
    phase = _phase()

    coordinator.capture_flowgraph_snapshot(
        FlowgraphSnapshotPayload(
            func_ea=0x401000,
            provider_phase=phase,
            snapshot=snapshot,
        )
    )

    assert runtime.attachments == [(0x401000, phase, snapshot)]
