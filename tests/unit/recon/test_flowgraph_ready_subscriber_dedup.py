"""Unit cover for E4a's ``FLOWGRAPH_READY`` -> recon dedup contract.

E4a moves microcode recon collection from two direct
``run_microcode_collectors(mba, ...)`` calls in
``hexrays_hooks.py`` to a single ``FLOWGRAPH_READY`` subscriber on
``D810``.  Both maturity-transition gates still emit
``FLOWGRAPH_READY`` for the same ``(func_ea, maturity)``, so the
subscriber fires twice -- but ``ReconPhase.run_microcode_collectors``
dedupes by ``(func_ea, maturity)`` internally, so exactly one
collector pass actually runs.

This file tests two things:

1. **Behavior**: emitting an event twice for the same
   ``(func_ea, maturity)`` results in exactly one collector
   invocation.  Uses a local sentinel ``Event`` enum -- the dedup
   contract is between ``EventEmitter`` and ``ReconPhase``, neither
   of which cares about the specific event identity.  Avoiding the
   real ``DecompilationEvent`` import keeps this file under the
   ``unit-tests-no-hexrays`` contract.
2. **Architectural pin**: no remaining direct
   ``self._recon_phase.run_microcode_collectors(mba, ...)`` /
   ``self._recon_phase.run_microcode_collectors(mba,`` call shape in
   the two manager maturity gates in ``hexrays_hooks.py``.  Catches
   future drift that re-introduces the double-collection path.

Lives in ``tests/unit/`` because:

* The dedup behavior is exercised purely through ``ReconPhase`` and
  ``EventEmitter`` -- no IDA imports needed.
* The architectural pin is a text-grep over the source.
"""

from __future__ import annotations

import enum
import time
from pathlib import Path
from types import MappingProxyType

from d810.ir.flowgraph import FlowGraph
from d810.core.events import EventEmitter
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.analyses.control_flow.models import ReconResult
from d810.passes.phase import ReconPhase


class _Event(enum.Enum):
    """Local sentinel stand-in for ``DecompilationEvent.FLOWGRAPH_READY``.

    The dedup behavior under test is in ``ReconPhase``, not in the
    event identity -- ``EventEmitter`` just routes kwargs by enum
    member.  Using a local enum keeps this unit test from
    transitively importing ``d810.hexrays.*``."""

    FLOWGRAPH_READY = "flowgraph.ready"


class _StubStore:
    """Minimal ``ReconStore``-shaped stub: just the attribute
    ``ReconPhase`` reads (``db_path``).  No actual save needed --
    we replace ``get_recon_writer`` with a stub at the test level
    instead."""

    db_path = Path(":memory:")


class _CountingCollector:
    """A microcode collector that records every ``collect()``
    invocation.  Counts let the test prove exactly-one-fire."""

    def __init__(self) -> None:
        self.name = "CountingCollector"
        self.maturities = None  # ALL_MATURITIES
        self.level = "microcode"
        self.calls: list[tuple[object, int, int]] = []

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        self.calls.append((target, func_ea, maturity))
        return ReconResult(
            collector_name=self.name,
            func_ea=func_ea,
            maturity=maturity,
            timestamp=time.time(),
            metrics=MappingProxyType({}),
            candidates=(),
        )


class _NoopWriter:
    """``ReconStore.get_recon_writer``-shaped stub that drops saves."""

    def submit(self, fn) -> None:
        pass

    def flush(self) -> None:
        pass


class _CapturingFactRuntime:
    """``FactLifecycleRuntime``-shaped stub for pre-D810 fact capture."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def capture_maturity_facts(
        self,
        target,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
        phase: str,
        snapshot,
    ) -> None:
        self.calls.append(
            {
                "target": target,
                "func_ea": func_ea,
                "provider_phase": provider_phase,
                "phase": phase,
                "snapshot": snapshot,
            }
        )


class TestFlowGraphReadySubscriberDedup:
    """Subscriber pattern: ``FLOWGRAPH_READY`` fires from two manager
    maturity gates per maturity transition.  ``ReconPhase`` dedupes by
    ``(func_ea, maturity)`` -- exactly one collector pass runs even
    though the subscriber is invoked twice."""

    def _build_phase(self, monkeypatch, collector: _CountingCollector) -> ReconPhase:
        """Build a ``ReconPhase`` with the writer stubbed so saves
        don't try to hit SQLite."""
        import d810.passes.phase

        monkeypatch.setattr(
            d810.passes.phase, "get_recon_writer", lambda _: _NoopWriter()
        )

        phase = ReconPhase(store=_StubStore())  # type: ignore[arg-type]
        phase.register(collector)
        return phase

    def _empty_flow_graph(self, func_ea: int, maturity: int) -> FlowGraph:
        """Pure ``FlowGraph`` with the lifter's E2b metadata contract."""
        return FlowGraph(
            blocks={},
            entry_serial=0,
            func_ea=func_ea,
            metadata={
                "maturity": maturity,
                "maturity_name": f"MMAT_{maturity}",
                "cpu_arch_name": "metapc",
            },
        )

    def _subscriber(
        self,
        phase: ReconPhase | None = None,
        *,
        fact_runtime: _CapturingFactRuntime | None = None,
    ):
        """E4a subscriber shape (mirrors
        ``manager._collect_recon_on_flowgraph_ready`` without
        importing ``manager.py`` -- which would pull IDA into the
        unit graph)."""
        def handler(
            *,
            flow_graph,
            func_ea,
            maturity,
            maturity_name,
            snapshot=None,
        ):
            provider_phase = ProviderPhaseSnapshot(
                provider_name="hexrays_microcode",
                provider_level=int(maturity),
                friendly_provider_level=str(maturity_name),
            )
            if phase is not None:
                phase.run_microcode_collectors(
                    flow_graph,
                    func_ea=int(func_ea),
                    provider_phase=provider_phase,
                )
            if fact_runtime is not None and snapshot is not None:
                fact_runtime.capture_maturity_facts(
                    flow_graph,
                    func_ea=int(func_ea),
                    provider_phase=provider_phase,
                    phase="pre_d810",
                    snapshot=snapshot,
                )

        return handler

    def test_two_events_same_func_maturity_yields_one_collect(
        self, monkeypatch
    ) -> None:
        """Two ``FLOWGRAPH_READY`` events for the same
        ``(func_ea, maturity)`` -- e.g. both manager maturity gates
        emitting at the same MMAT transition -- yield exactly one
        ``collector.collect()`` call."""
        collector = _CountingCollector()
        phase = self._build_phase(monkeypatch, collector)
        emitter: EventEmitter[_Event] = EventEmitter()
        emitter.on(_Event.FLOWGRAPH_READY, self._subscriber(phase))

        fg = self._empty_flow_graph(func_ea=0x140002000, maturity=14)

        # Emit twice for the same (func_ea, maturity).
        emitter.emit(
            _Event.FLOWGRAPH_READY,
            flow_graph=fg,
            func_ea=0x140002000,
            maturity=14,
            maturity_name="MMAT_GLBOPT1",
        )
        emitter.emit(
            _Event.FLOWGRAPH_READY,
            flow_graph=fg,
            func_ea=0x140002000,
            maturity=14,
            maturity_name="MMAT_GLBOPT1",
        )

        # Exactly one collector pass.
        assert len(collector.calls) == 1
        target, func_ea, maturity = collector.calls[0]
        assert target is fg
        assert func_ea == 0x140002000
        assert maturity == 14

    def test_different_maturities_yield_separate_collects(
        self, monkeypatch
    ) -> None:
        """Different maturities for the same function must NOT
        collapse -- the dedup key is ``(func_ea, maturity)``, not
        ``func_ea`` alone."""
        collector = _CountingCollector()
        phase = self._build_phase(monkeypatch, collector)
        emitter: EventEmitter[_Event] = EventEmitter()
        emitter.on(_Event.FLOWGRAPH_READY, self._subscriber(phase))

        fg14 = self._empty_flow_graph(func_ea=0x140002000, maturity=14)
        fg15 = self._empty_flow_graph(func_ea=0x140002000, maturity=15)

        emitter.emit(
            _Event.FLOWGRAPH_READY,
            flow_graph=fg14,
            func_ea=0x140002000,
            maturity=14,
            maturity_name="MMAT_GLBOPT1",
        )
        emitter.emit(
            _Event.FLOWGRAPH_READY,
            flow_graph=fg15,
            func_ea=0x140002000,
            maturity=15,
            maturity_name="MMAT_GLBOPT2",
        )

        assert len(collector.calls) == 2
        assert {m for _, _, m in collector.calls} == {14, 15}

    def test_different_functions_yield_separate_collects(
        self, monkeypatch
    ) -> None:
        """Different ``func_ea`` -- e.g. nested decompilations -- must
        NOT collapse either."""
        collector = _CountingCollector()
        phase = self._build_phase(monkeypatch, collector)
        emitter: EventEmitter[_Event] = EventEmitter()
        emitter.on(_Event.FLOWGRAPH_READY, self._subscriber(phase))

        fg_a = self._empty_flow_graph(func_ea=0x140002000, maturity=14)
        fg_b = self._empty_flow_graph(func_ea=0x140003000, maturity=14)

        emitter.emit(
            _Event.FLOWGRAPH_READY,
            flow_graph=fg_a,
            func_ea=0x140002000,
            maturity=14,
            maturity_name="MMAT_GLBOPT1",
        )
        emitter.emit(
            _Event.FLOWGRAPH_READY,
            flow_graph=fg_b,
            func_ea=0x140003000,
            maturity=14,
            maturity_name="MMAT_GLBOPT1",
        )

        assert len(collector.calls) == 2
        assert {func_ea for _, func_ea, _ in collector.calls} == {
            0x140002000,
            0x140003000,
        }

    def test_fact_capture_waits_for_snapshot_event(self) -> None:
        """Pre-D810 fact capture uses the block-manager event because
        only that producer carries the diagnostic snapshot.  A
        preceding instruction-manager event for the same maturity has
        no snapshot and must not consume the fact-capture path."""
        fact_runtime = _CapturingFactRuntime()
        emitter: EventEmitter[_Event] = EventEmitter()
        emitter.on(
            _Event.FLOWGRAPH_READY,
            self._subscriber(fact_runtime=fact_runtime),
        )

        fg = self._empty_flow_graph(func_ea=0x140002000, maturity=14)
        snapshot = object()

        emitter.emit(
            _Event.FLOWGRAPH_READY,
            flow_graph=fg,
            func_ea=0x140002000,
            maturity=14,
            maturity_name="MMAT_GLBOPT1",
        )
        assert fact_runtime.calls == []

        emitter.emit(
            _Event.FLOWGRAPH_READY,
            flow_graph=fg,
            func_ea=0x140002000,
            maturity=14,
            maturity_name="MMAT_GLBOPT1",
            snapshot=snapshot,
        )

        assert len(fact_runtime.calls) == 1
        call = fact_runtime.calls[0]
        assert call["target"] is fg
        assert call["func_ea"] == 0x140002000
        assert call["phase"] == "pre_d810"
        assert call["snapshot"] is snapshot
        provider_phase = call["provider_phase"]
        assert isinstance(provider_phase, ProviderPhaseSnapshot)
        assert provider_phase.provider_name == "hexrays_microcode"
        assert provider_phase.provider_level == 14
        assert provider_phase.friendly_provider_level == "MMAT_GLBOPT1"


class TestNoDirectReconCallsInManagerGates:
    """Architectural pin: ``hexrays_hooks.py`` must not contain any
    direct ``self._recon_phase.run_microcode_collectors(mba, ...)``
    call.  After E4a, all microcode recon collection goes through the
    ``FLOWGRAPH_READY`` subscriber on ``D810``.

    Catches drift -- a future edit that adds a direct call back would
    cause double-collection (the subscriber + the direct call).
    """

    def test_no_direct_run_microcode_collectors_call_in_hexrays_hooks(
        self,
    ) -> None:
        # ``__file__`` is .../tests/unit/recon/<file>.py -- the worktree
        # root is parents[3], then walk down to the source file.
        hexrays_hooks_path = (
            Path(__file__).resolve().parents[3]
            / "src"
            / "d810"
            / "hexrays"
            / "hooks"
            / "hexrays_hooks.py"
        )
        assert hexrays_hooks_path.exists(), (
            f"Resolved hexrays_hooks.py path {hexrays_hooks_path} does not "
            "exist -- check parents[N] offset"
        )

        src = hexrays_hooks_path.read_text()

        # Direct call shape -- the call form, not the mention of
        # ``run_microcode_collectors`` in comments / docstrings.
        forbidden = (
            "self._recon_phase.run_microcode_collectors(",
            "_recon_phase.run_microcode_collectors(\n",
        )
        for shape in forbidden:
            assert shape not in src, (
                f"hexrays_hooks.py contains a direct call to "
                f"``run_microcode_collectors`` ({shape!r}).  "
                "E4a moved this to the ``FLOWGRAPH_READY`` subscriber "
                "on ``D810`` (see "
                "``manager._collect_recon_on_flowgraph_ready``).  "
                "A direct call here would double-collect because the "
                "subscriber already fires per maturity transition."
            )

    def test_no_direct_pre_d810_fact_capture_call_in_hexrays_hooks(
        self,
    ) -> None:
        """E4b contract: the block-manager gate must not call
        ``capture_maturity_facts(mba, ...)`` directly.  Pre-D810
        facts now route through the same ``FLOWGRAPH_READY`` payload
        as recon collection."""
        hexrays_hooks_path = (
            Path(__file__).resolve().parents[3]
            / "src"
            / "d810"
            / "hexrays"
            / "hooks"
            / "hexrays_hooks.py"
        )
        assert hexrays_hooks_path.exists(), (
            f"Resolved hexrays_hooks.py path {hexrays_hooks_path} does not "
            "exist -- check parents[N] offset"
        )

        src = hexrays_hooks_path.read_text()
        assert "self._recon_runtime.capture_maturity_facts(" not in src, (
            "hexrays_hooks.py must not call "
            "self._recon_runtime.capture_maturity_facts(...) directly. "
            "Pre-D810 fact capture is owned by "
            "manager._collect_recon_on_flowgraph_ready so the target is the "
            "portable FlowGraph, not the live mba_t."
        )

    def test_post_d810_fact_capture_does_not_fallback_to_live_mba(
        self,
    ) -> None:
        """E4b contract: post-D810 facts must use the Hex-Rays adapter,
        not send live ``mba_t`` into the fact runtime on adapter failure."""
        manager_path = (
            Path(__file__).resolve().parents[3]
            / "src"
            / "d810"
            / "manager.py"
        )
        assert manager_path.exists(), (
            f"Resolved manager.py path {manager_path} does not exist -- "
            "check parents[N] offset"
        )

        src = manager_path.read_text()
        assert "falling back to live mba" not in src
        assert "target = mba\n" not in src
        assert "target = mba_to_fact_target(mba)" in src
        assert "skipping fact capture" in src
        assert "return\n            self._recon_runtime.capture_maturity_facts(" in src
