"""Tests for the maturity fact runtime."""
from __future__ import annotations

import d810.passes.fact_runtime as facts_runtime_module
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.core import ProviderPhaseSnapshot
from d810.core.observability import SnapshotRef
from d810.core.settings import configure_settings, reset_settings
from d810.passes.fact_runtime import FactCollectionResult, FactLifecycleRuntime
from d810.analyses.value_flow.facts import FactMapping, FactObservation, FactStatus
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

_MATURITY_LOCOPT = _MATURITY_VALUES["MMAT_LOCOPT"]
_MATURITY_CALLS = _MATURITY_VALUES["MMAT_CALLS"]
_MATURITY_GLBOPT1 = _MATURITY_VALUES["MMAT_GLBOPT1"]


def _phase(level: int, friendly: str | None = None) -> ProviderPhaseSnapshot:
    return ProviderPhaseSnapshot(
        provider_name="hexrays_microcode",
        provider_level=int(level),
        friendly_provider_level=friendly or f"MMAT_{int(level)}",
    )


def _flow_graph_with_insn_ea(*, block_serial: int, insn_ea: int) -> FlowGraph:
    return FlowGraph(
        blocks={
            block_serial: BlockSnapshot(
                serial=block_serial,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=insn_ea,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=1,
                        ea=insn_ea,
                        operands=(),
                        kind=InsnKind.MOV,
                    ),
                ),
            )
        },
        entry_serial=block_serial,
        func_ea=0x401000,
        metadata={
            "maturity": _MATURITY_GLBOPT1,
            "maturity_name": "MMAT_GLBOPT1",
            "cpu_arch_name": "metapc",
        },
    )

_TEST_REF = SnapshotRef(
    key="fact-runtime-test",
    func_ea=0x401000,
    label="test",
    maturity="MMAT_GLBOPT1",
    phase="pre_d810",
)


class _Collector:
    name = "fake-induction"
    fact_kinds = frozenset({"InductionCarrierFact"})
    maturities = frozenset({1})

    def collect(self, target, *, func_ea: int, maturity: int, phase: str):
        return (
            FactObservation(
                fact_id="induction:blk10",
                kind="InductionCarrierFact",
                semantic_key="loop:counter",
                maturity=f"MMAT_{maturity}",
                phase=phase,
                confidence=1.0,
                source_block=10,
            ),
        )


class _MappingCollector:
    name = "fake-mapping"
    maturities = None

    def collect(self, target, *, func_ea: int, maturity: int, phase: str):
        return FactCollectionResult(
            mappings=(
                FactMapping(
                    source_fact_id="induction:blk10",
                    source_maturity="MMAT_LOCOPT",
                    target_maturity=f"MMAT_{maturity}",
                    status=FactStatus.REMAPPED,
                    confidence=1.0,
                ),
            )
        )


def teardown_function() -> None:
    reset_settings()


def test_capture_persists_collector_observations_when_snapshot_is_available() -> None:
    configure_settings(fact_lifecycle=True)
    calls = []

    def _persist(
        snapshot, func_ea, observations, mappings, conflicts
    ) -> None:
        calls.append((snapshot, func_ea, observations, mappings, conflicts))

    runtime = FactLifecycleRuntime(persistence_callback=_persist)
    runtime.register(_Collector())

    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="pre_d810",
        snapshot=_TEST_REF,
    )

    assert summary.invoked is True
    assert summary.observation_count == 1
    assert len(calls) == 1
    assert calls[0][0] is _TEST_REF
    assert calls[0][1] == 0x401000
    assert calls[0][2][0].fact_id == "induction:blk10"
    assert calls[0][3] == ()
    assert calls[0][4] == ()


def test_capture_runs_in_production_without_diagnostic_snapshot() -> None:
    """Regression guard for 217716af2: pre-D810 fact capture is a PRODUCTION
    path that feeds return-leak suppression.  It MUST run (collectors fire,
    in-memory store populated) even when ``snapshot is None`` -- the normal
    non-diagnostic case.  Gating capture on the diagnostic snapshot silently
    disabled it in production and un-suppressed leaked terminal constants
    (sub_7FFD ``return 0xC5FB34A1D9A6E315``); full diagnostics masked the
    failure because the snapshot only ever existed under --full-diagnostics.
    """
    configure_settings(fact_lifecycle=True)
    calls: list = []
    runtime = FactLifecycleRuntime(
        persistence_callback=lambda *args: calls.append(args)
    )
    runtime.register(_Collector())

    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="pre_d810",
        snapshot=None,
    )

    # Capture ran: collector fired and the in-memory store is populated.
    assert summary.invoked is True
    assert summary.observation_count == 1
    view = runtime.validated_view(0x401000, 1)
    assert {obs.fact_id for obs in view.observations} == {"induction:blk10"}
    # No diagnostic snapshot -> nothing persisted to the diag DB, but the
    # facts are NOT dropped (they live in the in-memory store above).
    assert calls == []


def test_diag_attaches_when_snapshot_arrives_after_no_snapshot_event() -> None:
    """Dedup split: the no-snapshot InstructionOptimizerManager event can win
    the (func_ea, maturity, phase) capture race ahead of the snapshot-bearing
    BlockOptimizerManager event.  Capture fires once (first event); the later
    snapshot-bearing duplicate event must still attach the retained facts to
    the diagnostic snapshot exactly once.
    """
    configure_settings(fact_lifecycle=True)
    calls: list = []
    runtime = FactLifecycleRuntime(
        persistence_callback=lambda *args: calls.append(args)
    )
    runtime.register(_Collector())

    # Event 1: no snapshot (production capture) -- collector runs, nothing
    # persisted yet.
    first = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="pre_d810",
        snapshot=None,
    )
    assert first.invoked is True
    assert calls == []

    # Event 2: SAME key, now carrying the diagnostic snapshot -- capture is
    # already fired (collector does NOT re-run) but the retained payload is
    # flushed to the snapshot.
    second = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="pre_d810",
        snapshot=_TEST_REF,
    )
    assert second.invoked is False
    assert second.reason == "already-fired"
    assert len(calls) == 1
    assert calls[0][0] is _TEST_REF
    assert {obs.fact_id for obs in calls[0][2]} == {"induction:blk10"}


def test_diag_attachment_is_not_double_persisted() -> None:
    """A snapshot-bearing event followed by a duplicate snapshot-bearing event
    for the same key persists exactly once (idempotent via ``_persisted``)."""
    configure_settings(fact_lifecycle=True)
    calls: list = []
    runtime = FactLifecycleRuntime(
        persistence_callback=lambda *args: calls.append(args)
    )
    runtime.register(_Collector())

    runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="pre_d810",
        snapshot=_TEST_REF,
    )
    runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="pre_d810",
        snapshot=_TEST_REF,
    )

    assert len(calls) == 1


def test_capture_persists_collector_mappings() -> None:
    configure_settings(fact_lifecycle=True)
    calls = []
    runtime = FactLifecycleRuntime(
        persistence_callback=lambda *args: calls.append(args)
    )
    runtime.register(_MappingCollector())

    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(4),
        snapshot=_TEST_REF,
    )

    assert summary.mapping_count == 1
    # signature: (snapshot, func_ea, observations, mappings, conflicts)
    assert calls[0][3][0].source_fact_id == "induction:blk10"


def test_find_block_for_ea_supports_flow_graph_snapshots() -> None:
    flow_graph = _flow_graph_with_insn_ea(block_serial=42, insn_ea=0x401234)

    assert FactLifecycleRuntime._find_block_for_ea(flow_graph, 0x401234) == 42
    assert FactLifecycleRuntime._find_block_for_ea(flow_graph, 0xDEADBEEF) is None


def test_capture_summary_log_uses_maturity_name(monkeypatch) -> None:
    configure_settings(fact_lifecycle=True)
    messages: list[str] = []

    def _record_info(message, *args, **_kwargs) -> None:
        messages.append(message % args)

    monkeypatch.setattr(facts_runtime_module.logger, "info", _record_info)

    runtime = FactLifecycleRuntime()
    runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(_MATURITY_CALLS, "MMAT_CALLS"),
        phase="pre_d810",
    )

    capture_lines = [
        message
        for message in messages
        if message.startswith("FACT_LIFECYCLE_CAPTURE")
    ]
    assert capture_lines
    assert "maturity=MMAT_CALLS" in capture_lines[0]
    assert f"maturity={_MATURITY_CALLS}" not in capture_lines[0]


def test_validated_view_accumulates_observations_and_filters_stale_mappings() -> None:
    class _StaleMappingCollector:
        name = "stale-mapping"
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return FactCollectionResult(
                mappings=(
                    FactMapping(
                        source_fact_id="induction:blk10",
                        source_maturity="MMAT_1",
                        target_maturity="MMAT_2",
                        status=FactStatus.STALE,
                        confidence=0.5,
                    ),
                )
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Collector())
    runtime.register(_StaleMappingCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    active_before = runtime.validated_view(0x401000, 1)
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    active_after = runtime.validated_view(0x401000, "MMAT_2")

    assert len(active_before.observations) == 1
    assert len(active_before.active_observations) == 1
    assert active_after.maturity == "MMAT_2"
    assert len(active_after.observations) == 1
    assert len(active_after.mappings) == 1
    assert active_after.active_observations == ()


def test_validated_view_is_historically_scoped() -> None:
    class _LateStaleMappingCollector:
        name = "late-stale-mapping"
        maturities = frozenset({3})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return FactCollectionResult(
                mappings=(
                    FactMapping(
                        source_fact_id="induction:blk10",
                        source_maturity="MMAT_1",
                        target_maturity="MMAT_3",
                        status=FactStatus.STALE,
                        confidence=0.5,
                    ),
                )
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Collector())
    runtime.register(_LateStaleMappingCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(3), phase="pre_d810")

    calls_view = runtime.validated_view(0x401000, "MMAT_2")
    glbopt1_view = runtime.validated_view(0x401000, "MMAT_3")

    assert len(calls_view.observations) == 1
    assert calls_view.mappings == ()
    assert len(calls_view.active_observations) == 1
    assert len(glbopt1_view.mappings) == 1
    assert glbopt1_view.active_observations == ()


def test_induction_fact_absence_creates_identity_lost_mapping() -> None:
    class _InductionCollector:
        name = "induction-runs-at-both-maturities"
        fact_kinds = frozenset({"InductionCarrierFact"})
        maturities = frozenset({1, 2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            if maturity != 1:
                return ()
            return (
                FactObservation(
                    fact_id="induction:blk10",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=1.0,
                    source_block=10,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InductionCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    calls_view = runtime.validated_view(0x401000, "MMAT_2")

    assert len(calls_view.observations) == 1
    assert len(calls_view.mappings) == 1
    mapping = calls_view.mappings[0]
    assert mapping.source_fact_id == "induction:blk10"
    assert mapping.status is FactStatus.IDENTITY_LOST
    assert mapping.target_maturity == FactLifecycleRuntime._maturity_text(2)
    assert mapping.target_block is None
    assert mapping.target_ea is None
    assert mapping.target_mop_signature is None
    assert mapping.payload["source_block"] == 10
    assert calls_view.active_observations == ()


def test_induction_does_not_infer_loss_when_collector_did_not_run() -> None:
    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Collector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    calls_view = runtime.validated_view(0x401000, "MMAT_2")

    assert calls_view.mappings == ()
    assert len(calls_view.active_observations) == 1


def test_induction_identity_lost_is_per_fact_id_not_semantic_key() -> None:
    class _InitialCollector:
        name = "initial-two-facts"
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:blk10",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=1.0,
                    source_block=10,
                ),
                FactObservation(
                    fact_id="induction:blk11",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=1.0,
                    source_block=11,
                ),
            )

    class _PartialSurvivalCollector:
        name = "partial-survival"
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:blk10",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_2",
                    phase=phase,
                    confidence=1.0,
                    source_block=10,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InitialCollector())
    runtime.register(_PartialSurvivalCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert [mapping.source_fact_id for mapping in view.mappings] == ["induction:blk11"]
    assert {obs.fact_id for obs in view.active_observations} == {"induction:blk10"}


def test_induction_fact_remaps_on_stable_block_mop_continuity() -> None:
    class _InitialCollector:
        name = "initial-remap-source"
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:old",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.9,
                    source_block=10,
                    source_ea=0x1000,
                    mop_signature="mop_S:0x680:8",
                ),
            )

    class _RemappedCollector:
        name = "remapped-target"
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:new",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_2",
                    phase=phase,
                    confidence=0.8,
                    source_block=10,
                    source_ea=0x2000,
                    mop_signature="mop_S:0x680:8",
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InitialCollector())
    runtime.register(_RemappedCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.REMAPPED
    assert mapping.source_fact_id == "induction:old"
    assert mapping.target_fact_id == "induction:new"
    assert mapping.target_block == 10
    assert mapping.target_ea == 0x2000
    assert mapping.target_mop_signature == "mop_S:0x680:8"
    assert {obs.fact_id for obs in view.active_observations} == {"induction:new"}


def test_induction_fact_remaps_on_stable_source_ea_mop_continuity() -> None:
    class _InitialCollector:
        name = "initial-source-ea-remap-source"
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:old",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.9,
                    source_block=265,
                    source_ea=0x180015F08,
                    mop_signature="mop_S:writeback:dest=0x638:source=0x468:8",
                ),
            )

    class _RemappedCollector:
        name = "remapped-source-ea-target"
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:new",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_2",
                    phase=phase,
                    confidence=0.8,
                    source_block=184,
                    source_ea=0x180015F08,
                    mop_signature="mop_S:writeback:dest=0x638:source=0x468:8",
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InitialCollector())
    runtime.register(_RemappedCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.REMAPPED
    assert mapping.source_fact_id == "induction:old"
    assert mapping.target_fact_id == "induction:new"
    assert mapping.target_block == 184
    assert mapping.target_ea == 0x180015F08
    assert mapping.target_mop_signature == (
        "mop_S:writeback:dest=0x638:source=0x468:8"
    )
    assert "source-EA/mop" in (mapping.reason or "")


def test_induction_source_ea_semantic_mismatch_is_contradicted() -> None:
    class _PriorCollector:
        name = "prior-source-ea-conflict-source"
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:old",
                    kind="InductionCarrierFact",
                    semantic_key="loop:old",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.9,
                    source_block=265,
                    source_ea=0x180015F08,
                    mop_signature="mop_S:writeback:dest=0x638:source=0x468:8",
                ),
            )

    class _CurrentCollector:
        name = "current-source-ea-conflict-target"
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:new",
                    kind="InductionCarrierFact",
                    semantic_key="loop:new",
                    maturity="MMAT_2",
                    phase=phase,
                    confidence=0.8,
                    source_block=184,
                    source_ea=0x180015F08,
                    mop_signature="mop_S:writeback:dest=0x638:source=0x468:8",
                ),
            )

    configure_settings(fact_lifecycle=True)
    calls = []
    runtime = FactLifecycleRuntime(
        persistence_callback=lambda *args: calls.append(args)
    )
    runtime.register(_PriorCollector())
    runtime.register(_CurrentCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(2),
        phase="pre_d810",
        snapshot=_TEST_REF,
    )
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert summary.conflict_count == 1
    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.CONTRADICTED
    assert mapping.source_fact_id == "induction:old"
    assert mapping.target_fact_id is None
    conflicts = calls[0][4]
    assert len(conflicts) == 1
    assert conflicts[0].conflict_kind == "INCOMPATIBLE_INDUCTION_IDENTITY"
    assert conflicts[0].fact_id == "induction:new"
    assert conflicts[0].other_fact_id == "induction:old"
    assert conflicts[0].payload["continuity_source_ea"] == 0x180015F08


def test_induction_conflict_records_incompatible_same_block_mop_identity() -> None:
    class _ConflictingCollector:
        name = "conflicting-current"
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:a",
                    kind="InductionCarrierFact",
                    semantic_key="loop:a",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.9,
                    source_block=10,
                    mop_signature="mop_S:0x680:8",
                ),
                FactObservation(
                    fact_id="induction:b",
                    kind="InductionCarrierFact",
                    semantic_key="loop:b",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.9,
                    source_block=10,
                    mop_signature="mop_S:0x680:8",
                ),
            )

    configure_settings(fact_lifecycle=True)
    calls = []
    runtime = FactLifecycleRuntime(
        persistence_callback=lambda *args: calls.append(args)
    )
    runtime.register(_ConflictingCollector())

    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="pre_d810",
        snapshot=_TEST_REF,
    )

    assert summary.conflict_count == 1
    conflicts = calls[0][4]
    assert len(conflicts) == 1
    assert conflicts[0].conflict_kind == "INCOMPATIBLE_INDUCTION_IDENTITY"
    assert conflicts[0].fact_id == "induction:a"
    assert conflicts[0].other_fact_id == "induction:b"


def test_induction_prior_current_semantic_mismatch_is_contradicted() -> None:
    class _PriorCollector:
        name = "prior-conflict-source"
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:old",
                    kind="InductionCarrierFact",
                    semantic_key="loop:old",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.9,
                    source_block=10,
                    mop_signature="mop_S:0x680:8",
                ),
            )

    class _CurrentCollector:
        name = "current-conflict-target"
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="induction:new",
                    kind="InductionCarrierFact",
                    semantic_key="loop:new",
                    maturity="MMAT_2",
                    phase=phase,
                    confidence=0.8,
                    source_block=10,
                    mop_signature="mop_S:0x680:8",
                ),
            )

    configure_settings(fact_lifecycle=True)
    calls = []
    runtime = FactLifecycleRuntime(
        persistence_callback=lambda *args: calls.append(args)
    )
    runtime.register(_PriorCollector())
    runtime.register(_CurrentCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(2),
        phase="pre_d810",
        snapshot=_TEST_REF,
    )
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert summary.conflict_count == 1
    assert len(view.mappings) == 1
    assert view.mappings[0].status is FactStatus.CONTRADICTED
    assert view.mappings[0].source_fact_id == "induction:old"
    assert view.mappings[0].target_fact_id is None
    assert {obs.fact_id for obs in view.active_observations} == {"induction:new"}
    conflicts = calls[0][4]
    assert len(conflicts) == 1
    assert conflicts[0].conflict_kind == "INCOMPATIBLE_INDUCTION_IDENTITY"
    assert conflicts[0].fact_id == "induction:new"
    assert conflicts[0].other_fact_id == "induction:old"


def test_induction_identity_lost_mapping_is_not_duplicated() -> None:
    class _InductionCollector:
        name = "induction-runs-at-both-maturities-dedupe"
        fact_kinds = frozenset({"InductionCarrierFact"})
        maturities = frozenset({1, 2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            if maturity != 1:
                return ()
            return (
                FactObservation(
                    fact_id="induction:blk10",
                    kind="InductionCarrierFact",
                    semantic_key="loop:counter",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=1.0,
                    source_block=10,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InductionCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    first_mapping_count = len(runtime.validated_view(0x401000, "MMAT_2").mappings)
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="post_d810")
    second_mapping_count = len(runtime.validated_view(0x401000, "MMAT_2").mappings)

    assert first_mapping_count == 1
    assert second_mapping_count == 1


def test_return_carrier_fact_gets_identity_lost_mapping() -> None:
    class _Insn:
        def __init__(self, ea: int, next_insn=None) -> None:
            self.ea = ea
            self.next = next_insn

    class _Block:
        def __init__(self, head) -> None:
            self.head = head

    class _Target:
        qty = 12

        def get_mblock(self, serial: int):
            if int(serial) == 7:
                return _Block(_Insn(0x1000))
            return _Block(None)

    class _ReturnCarrierCollector:
        name = "return-carrier"
        fact_kinds = frozenset({"ReturnCarrierFact"})
        maturities = frozenset({1, 2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            if maturity != 1:
                return ()
            return (
                FactObservation(
                    fact_id="return_carrier:slot=0x7f0:blk=10",
                    kind="ReturnCarrierFact",
                    semantic_key=(
                        "return_carrier:slot=0x7f0:class=stack_identity_carrier:"
                        "source=mop_S:0x680"
                    ),
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.86,
                    source_block=10,
                    source_ea=0x1000,
                    mop_signature="return_slot:mop_S:0x7f0:8",
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_ReturnCarrierCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(_Target(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.IDENTITY_LOST
    assert mapping.source_fact_id == "return_carrier:slot=0x7f0:blk=10"
    assert mapping.target_fact_id is None
    assert mapping.target_block == 7
    assert mapping.target_ea == 0x1000
    assert mapping.payload["kind"] == "ReturnCarrierFact"
    assert mapping.payload["source_payload"] == {}
    assert {obs.fact_id for obs in view.active_observations} == set()


def test_return_carrier_does_not_infer_loss_when_collector_did_not_run() -> None:
    class _ReturnCarrierCollector:
        name = "return-carrier"
        fact_kinds = frozenset({"ReturnCarrierFact"})
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="return_carrier:slot=0x7f0:blk=10",
                    kind="ReturnCarrierFact",
                    semantic_key=(
                        "return_carrier:slot=0x7f0:class=stack_identity_carrier:"
                        "source=mop_S:0x680"
                    ),
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.86,
                    source_block=10,
                    source_ea=0x1000,
                    mop_signature="return_slot:mop_S:0x7f0:8",
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_ReturnCarrierCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert view.mappings == ()
    assert len(view.active_observations) == 1


def test_terminal_byte_emitter_fact_gets_identity_lost_mapping() -> None:
    class _ByteEmitterCollector:
        name = "terminal-byte"
        fact_kinds = frozenset({"TerminalByteEmitterFact"})
        maturities = frozenset({1, 2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            if maturity != 1:
                return ()
            return (
                FactObservation(
                    fact_id="terminal_byte_emitter:byte2:blk=101",
                    kind="TerminalByteEmitterFact",
                    semantic_key=(
                        "terminal_byte_emitter:byte_index=2:"
                        "dest=%var_dst.8:counter=%var_53.8"
                    ),
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.72,
                    source_block=101,
                    source_ea=0x180014101,
                    mop_signature=(
                        "terminal_byte_emit:byte=2:"
                        "dest=%var_dst.8:counter=%var_53.8"
                    ),
                    payload={"byte_index": 2},
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_ByteEmitterCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.IDENTITY_LOST
    assert mapping.source_fact_id == "terminal_byte_emitter:byte2:blk=101"
    assert mapping.target_fact_id is None
    assert mapping.target_block is None
    assert mapping.payload["kind"] == "TerminalByteEmitterFact"
    assert mapping.payload["byte_index"] == 2
    assert view.active_observations == ()


def test_terminal_byte_emitter_does_not_infer_loss_when_collector_did_not_run() -> None:
    class _ByteEmitterCollector:
        name = "terminal-byte"
        fact_kinds = frozenset({"TerminalByteEmitterFact"})
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="terminal_byte_emitter:byte2:blk=101",
                    kind="TerminalByteEmitterFact",
                    semantic_key=(
                        "terminal_byte_emitter:family=terminal_tail:"
                        "byte_index=2:dest=%var_dst.8:counter=%var_53.8"
                    ),
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.72,
                    source_block=101,
                    source_ea=0x180014101,
                    mop_signature=(
                        "terminal_byte_emit:family=terminal_tail:"
                        "byte=2:dest=%var_dst.8:counter=%var_53.8"
                    ),
                    payload={"byte_index": 2},
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_ByteEmitterCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert view.mappings == ()
    assert len(view.active_observations) == 1


def test_terminal_byte_emitter_fact_remaps_on_stable_source_ea_mop() -> None:
    class _InitialCollector:
        name = "terminal-byte-initial"
        fact_kinds = frozenset({"TerminalByteEmitterFact"})
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="terminal_byte_emitter:byte2:blk=101",
                    kind="TerminalByteEmitterFact",
                    semantic_key=(
                        "terminal_byte_emitter:byte_index=2:"
                        "dest=%var_dst.8:counter=%var_53.8"
                    ),
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.72,
                    source_block=101,
                    source_ea=0x180014101,
                    mop_signature=(
                        "terminal_byte_emit:byte=2:"
                        "dest=%var_dst.8:counter=%var_53.8"
                    ),
                    payload={"byte_index": 2},
                ),
            )

    class _CurrentCollector:
        name = "terminal-byte-current"
        fact_kinds = frozenset({"TerminalByteEmitterFact"})
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="terminal_byte_emitter:byte2:blk=132",
                    kind="TerminalByteEmitterFact",
                    semantic_key=(
                        "terminal_byte_emitter:byte_index=2:"
                        "dest=%var_dst.8:counter=%var_53.8"
                    ),
                    maturity="MMAT_2",
                    phase=phase,
                    confidence=0.7,
                    source_block=132,
                    source_ea=0x180014101,
                    mop_signature=(
                        "terminal_byte_emit:byte=2:"
                        "dest=%var_dst.8:counter=%var_53.8"
                    ),
                    payload={"byte_index": 2},
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InitialCollector())
    runtime.register(_CurrentCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.REMAPPED
    assert mapping.source_fact_id == "terminal_byte_emitter:byte2:blk=101"
    assert mapping.target_fact_id == "terminal_byte_emitter:byte2:blk=132"
    assert mapping.target_block == 132
    assert mapping.target_ea == 0x180014101
    assert {obs.fact_id for obs in view.active_observations} == {
        "terminal_byte_emitter:byte2:blk=132"
    }


def test_generic_structural_fact_gets_identity_lost_mapping_when_collector_ran() -> None:
    class _InitialCollector:
        name = "call-anchor-initial"
        fact_kinds = frozenset({"CallAnchorFact"})
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="call_anchor:old",
                    kind="CallAnchorFact",
                    semantic_key="call_anchor:kind=direct_call:target=$0x180000000",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.86,
                    source_block=130,
                    source_ea=0x180014848,
                    mop_signature="call:direct_call:$0x180000000",
                ),
            )

    class _EmptyCurrentCollector:
        name = "call-anchor-current"
        fact_kinds = frozenset({"CallAnchorFact"})
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return ()

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InitialCollector())
    runtime.register(_EmptyCurrentCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.IDENTITY_LOST
    assert mapping.source_fact_id == "call_anchor:old"
    assert mapping.payload["kind"] == "CallAnchorFact"
    assert view.active_observations == ()


def test_generic_structural_fact_remaps_on_stable_source_ea_mop() -> None:
    class _InitialCollector:
        name = "zero-blob-initial"
        fact_kinds = frozenset({"ZeroBlobFact"})
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="zero_blob:old",
                    kind="ZeroBlobFact",
                    semantic_key="zero_blob_init:kind=zero_store:dest=%var_dst.8:size=8",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.78,
                    source_block=40,
                    source_ea=0x180013000,
                    mop_signature="zero_blob:zero_store:dest=%var_dst.8:size=8",
                ),
            )

    class _CurrentCollector:
        name = "zero-blob-current"
        fact_kinds = frozenset({"ZeroBlobFact"})
        maturities = frozenset({2})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="zero_blob:new",
                    kind="ZeroBlobFact",
                    semantic_key="zero_blob_init:kind=zero_store:dest=%var_dst.8:size=8",
                    maturity="MMAT_2",
                    phase=phase,
                    confidence=0.76,
                    source_block=88,
                    source_ea=0x180013000,
                    mop_signature="zero_blob:zero_store:dest=%var_dst.8:size=8",
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InitialCollector())
    runtime.register(_CurrentCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.REMAPPED
    assert mapping.source_fact_id == "zero_blob:old"
    assert mapping.target_fact_id == "zero_blob:new"
    assert mapping.target_block == 88
    assert {obs.fact_id for obs in view.active_observations} == {"zero_blob:new"}


def test_generic_structural_fact_does_not_emit_loss_when_collector_did_not_run() -> None:
    class _InitialCollector:
        name = "return-frontier-initial"
        fact_kinds = frozenset({"ReturnFrontierFact"})
        maturities = frozenset({1})

        def collect(self, target, *, func_ea: int, maturity: int, phase: str):
            return (
                FactObservation(
                    fact_id="return_frontier:old",
                    kind="ReturnFrontierFact",
                    semantic_key="return_frontier:return_block=57",
                    maturity="MMAT_1",
                    phase=phase,
                    confidence=0.72,
                    source_block=57,
                    source_ea=0x180012000,
                    mop_signature="return_frontier:mop",
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_InitialCollector())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(1), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(2), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert view.mappings == ()
    assert {obs.fact_id for obs in view.active_observations} == {
        "return_frontier:old"
    }


def _state_write_obs(
    *,
    fact_id: str,
    maturity: str,
    block_serial: int,
    instruction_ea: int,
    state_const: int,
    state_var_stkoff: int = 0x3C,
    insn_index: int = 0,
) -> FactObservation:
    payload = {
        "state_const_hex": f"0x{state_const & 0xFFFFFFFFFFFFFFFF:016x}",
        "state_const_u64": state_const & 0xFFFFFFFFFFFFFFFF,
        "state_const": state_const & 0xFFFFFFFFFFFFFFFF,
        "block_serial": block_serial,
        "instruction_index": insn_index,
        "instruction_ea_hex": f"0x{instruction_ea & 0xFFFFFFFFFFFFFFFF:016x}",
        "instruction_ea": instruction_ea,
        "state_var_stkoff": state_var_stkoff,
        "state_var_stkoff_hex": f"0x{state_var_stkoff:x}",
        "successor_blocks": [],
        "opcode": "m_mov",
    }
    return FactObservation(
        fact_id=fact_id,
        kind="StateWriteAnchorFact",
        semantic_key=fact_id,
        maturity=maturity,
        phase="pre_d810",
        confidence=0.9,
        source_block=block_serial,
        source_ea=instruction_ea,
        mop_signature=f"state_write:mop_S:0x{state_var_stkoff:x}:4",
        payload=payload,
    )


def test_state_write_anchor_rewrite_emits_state_const_rewritten_mapping() -> None:
    """When LOCOPT-pre records state_const=A and a later maturity at the
    SAME (block_serial, instruction_ea, state_var_stkoff) records state_const=B
    with B != A, the lifecycle must emit STATE_CONST_REWRITTEN."""

    locopt = _MATURITY_LOCOPT
    glbopt1 = _MATURITY_GLBOPT1

    class _Pre:
        name = "state-write-pre"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({locopt})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=0:ea=0x180014155:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=100,
                    instruction_ea=0x180014155,
                    state_const=0x5A21D9DB,
                ),
            )

    class _Post:
        name = "state-write-post"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({glbopt1})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=0:ea=0x180014155:stkoff=0x3c",
                    maturity="MMAT_GLBOPT1",
                    block_serial=100,
                    instruction_ea=0x180014155,
                    state_const=0x63D54755,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Pre())
    runtime.register(_Post())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(locopt, "MMAT_LOCOPT"), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(glbopt1, "MMAT_GLBOPT1"), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_GLBOPT1")

    rewrite_mappings = [
        m for m in view.mappings if m.status is FactStatus.STATE_CONST_REWRITTEN
    ]
    assert len(rewrite_mappings) == 1
    mapping = rewrite_mappings[0]
    assert mapping.source_maturity == "MMAT_LOCOPT"
    assert mapping.target_maturity == "MMAT_GLBOPT1"
    assert mapping.payload["original_state_const"] == 0x5A21D9DB
    assert mapping.payload["rewritten_state_const"] == 0x63D54755
    assert mapping.payload["original_state_const_hex"] == "0x000000005a21d9db"
    assert mapping.payload["rewritten_state_const_hex"] == "0x0000000063d54755"
    assert mapping.payload["block_serial"] == 100
    assert mapping.payload["instruction_ea"] == 0x180014155
    assert mapping.payload["state_var_stkoff"] == 0x3C
    # Original LOCOPT-pre observation must remain ACTIVE -- it's still
    # the load-bearing record of the original const.
    assert any(
        obs.maturity == "MMAT_LOCOPT" for obs in view.active_observations
    )


def test_state_write_anchor_same_const_does_not_emit_rewrite() -> None:
    locopt = _MATURITY_LOCOPT
    glbopt1 = _MATURITY_GLBOPT1

    class _Pre:
        name = "state-write-pre-stable"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({locopt})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=42:insn=0:ea=0x42:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=42,
                    instruction_ea=0x42,
                    state_const=0xCAFE,
                ),
            )

    class _Post:
        name = "state-write-post-stable"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({glbopt1})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=42:insn=0:ea=0x42:stkoff=0x3c",
                    maturity="MMAT_GLBOPT1",
                    block_serial=42,
                    instruction_ea=0x42,
                    state_const=0xCAFE,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Pre())
    runtime.register(_Post())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(locopt, "MMAT_LOCOPT"), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(glbopt1, "MMAT_GLBOPT1"), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_GLBOPT1")

    assert not any(
        m.status is FactStatus.STATE_CONST_REWRITTEN for m in view.mappings
    )


def test_state_write_anchor_same_ea_const_changed_emits_rewrite() -> None:
    """Primary-key path: same EA, same block, same stkoff, different
    const -> STATE_CONST_REWRITTEN with original_ea_hex == rewritten_ea_hex."""

    locopt = _MATURITY_LOCOPT
    glbopt1 = _MATURITY_GLBOPT1

    class _Pre:
        name = "state-write-pre-same-ea"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({locopt})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=0:ea=0x180014155:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=100,
                    instruction_ea=0x180014155,
                    state_const=0x5A21D9DB,
                ),
            )

    class _Post:
        name = "state-write-post-same-ea"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({glbopt1})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=0:ea=0x180014155:stkoff=0x3c",
                    maturity="MMAT_GLBOPT1",
                    block_serial=100,
                    instruction_ea=0x180014155,
                    state_const=0x63D54755,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Pre())
    runtime.register(_Post())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(locopt, "MMAT_LOCOPT"), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(glbopt1, "MMAT_GLBOPT1"), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_GLBOPT1")

    rewrites = [
        m for m in view.mappings if m.status is FactStatus.STATE_CONST_REWRITTEN
    ]
    assert len(rewrites) == 1
    payload = rewrites[0].payload
    assert payload["original_ea_hex"] == payload["rewritten_ea_hex"]
    assert payload["ea_changed"] is False
    assert payload["continuity_kind"] == "primary_ea_block_stkoff"
    assert payload["original_const_hex"] == "0x000000005a21d9db"
    assert payload["rewritten_const_hex"] == "0x0000000063d54755"
    assert payload["original_const_u64"] == 0x5A21D9DB
    assert payload["rewritten_const_u64"] == 0x63D54755
    assert payload["from_maturity"] == "MMAT_LOCOPT"
    assert payload["to_maturity"] == "MMAT_GLBOPT1"
    assert payload["block_serial"] == 100
    assert payload["state_var_stkoff_hex"] == "0x3c"


def test_state_write_anchor_ea_changed_canonical_stkoff_emits_rewrite() -> None:
    """Fallback-key path: same block, same canonical stkoff, but EAs
    differ -> STATE_CONST_REWRITTEN with original_ea_hex !=
    rewritten_ea_hex and continuity_kind=fallback_canonical_state_var."""

    locopt = _MATURITY_LOCOPT
    calls = _MATURITY_CALLS

    class _Pre:
        name = "state-write-pre-ea-changed"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({locopt})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                # Several state-var writes plus one byte-table write so
                # the canonical stkoff (0x3c, count=3) wins the mode
                # vote against 0x68 (count=1).
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=0:ea=0x180013c5b:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=100,
                    instruction_ea=0x180013C5B,
                    state_const=0x5A21D9DB,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=54:insn=0:ea=0x180013800:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=54,
                    instruction_ea=0x180013800,
                    state_const=0x432DC789,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=161:insn=0:ea=0x180013a00:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=161,
                    instruction_ea=0x180013A00,
                    state_const=0x149AED27,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=5:ea=0x180013c80:stkoff=0x68",
                    maturity="MMAT_LOCOPT",
                    block_serial=100,
                    instruction_ea=0x180013C80,
                    state_const=0xAB,
                    state_var_stkoff=0x68,
                    insn_index=5,
                ),
            )

    class _Post:
        name = "state-write-post-ea-changed"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({calls})

        def collect(self, target, *, func_ea, maturity, phase):
            # Same block 100, same stkoff 0x3c, NEW EA, NEW const.
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=0:ea=0x18001450a:stkoff=0x3c",
                    maturity="MMAT_CALLS",
                    block_serial=100,
                    instruction_ea=0x18001450A,
                    state_const=0x63D54755,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Pre())
    runtime.register(_Post())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(locopt, "MMAT_LOCOPT"), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(calls, "MMAT_CALLS"), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_CALLS")

    rewrites = [
        m
        for m in view.mappings
        if m.status is FactStatus.STATE_CONST_REWRITTEN
        and m.payload.get("block_serial") == 100
        and m.payload.get("state_var_stkoff") == 0x3C
    ]
    assert len(rewrites) == 1
    payload = rewrites[0].payload
    assert payload["original_ea_hex"] == "0x0000000180013c5b"
    assert payload["rewritten_ea_hex"] == "0x000000018001450a"
    assert payload["original_ea_hex"] != payload["rewritten_ea_hex"]
    assert payload["ea_changed"] is True
    assert payload["continuity_kind"] == "fallback_canonical_state_var"
    assert payload["original_const_hex"] == "0x000000005a21d9db"
    assert payload["rewritten_const_hex"] == "0x0000000063d54755"
    assert payload["from_maturity"] == "MMAT_LOCOPT"
    assert payload["to_maturity"] == "MMAT_CALLS"


def test_state_write_anchor_fallback_ignores_different_block() -> None:
    """Fallback must NOT correlate observations across DIFFERENT blocks
    even when the canonical stkoff matches."""

    locopt = _MATURITY_LOCOPT
    calls = _MATURITY_CALLS

    class _Pre:
        name = "state-write-pre-different-block"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({locopt})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                # Make canonical stkoff = 0x3c (3 hits).
                _state_write_obs(
                    fact_id="state_write_anchor:blk=10:insn=0:ea=0x10:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=10,
                    instruction_ea=0x10,
                    state_const=0x1111,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=20:insn=0:ea=0x20:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=20,
                    instruction_ea=0x20,
                    state_const=0x2222,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=30:insn=0:ea=0x30:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=30,
                    instruction_ea=0x30,
                    state_const=0x3333,
                ),
            )

    class _Post:
        name = "state-write-post-different-block"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({calls})

        def collect(self, target, *, func_ea, maturity, phase):
            # Different block (40) with same canonical stkoff. None of
            # the prior observations should map to this one.
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=40:insn=0:ea=0x40:stkoff=0x3c",
                    maturity="MMAT_CALLS",
                    block_serial=40,
                    instruction_ea=0x40,
                    state_const=0x4444,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Pre())
    runtime.register(_Post())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(locopt, "MMAT_LOCOPT"), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(calls, "MMAT_CALLS"), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_CALLS")

    rewrites = [
        m for m in view.mappings if m.status is FactStatus.STATE_CONST_REWRITTEN
    ]
    assert rewrites == []


def test_state_write_anchor_fallback_skips_non_canonical_stkoff() -> None:
    """Fallback must NOT trigger for non-canonical stkoffs (e.g. byte
    table writes at 0x68/0x60). Different EAs at the same block but
    non-canonical stkoff -> no STATE_CONST_REWRITTEN mapping."""

    locopt = _MATURITY_LOCOPT
    calls = _MATURITY_CALLS

    class _Pre:
        name = "state-write-pre-non-canonical"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({locopt})

        def collect(self, target, *, func_ea, maturity, phase):
            # Canonical stkoff = 0x3c (3 hits at OTHER blocks). Block
            # 100 has a single 0x68 write (byte-table).
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=10:insn=0:ea=0x10:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=10,
                    instruction_ea=0x10,
                    state_const=0x1111,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=20:insn=0:ea=0x20:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=20,
                    instruction_ea=0x20,
                    state_const=0x2222,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=30:insn=0:ea=0x30:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=30,
                    instruction_ea=0x30,
                    state_const=0x3333,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=5:ea=0x100a:stkoff=0x68",
                    maturity="MMAT_LOCOPT",
                    block_serial=100,
                    instruction_ea=0x100A,
                    state_const=0xAA,
                    state_var_stkoff=0x68,
                    insn_index=5,
                ),
            )

    class _Post:
        name = "state-write-post-non-canonical"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({calls})

        def collect(self, target, *, func_ea, maturity, phase):
            # Same block 100, same non-canonical stkoff 0x68, NEW EA,
            # NEW const. Fallback MUST NOT correlate.
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=5:ea=0x100b:stkoff=0x68",
                    maturity="MMAT_CALLS",
                    block_serial=100,
                    instruction_ea=0x100B,
                    state_const=0xBB,
                    state_var_stkoff=0x68,
                    insn_index=5,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Pre())
    runtime.register(_Post())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(locopt, "MMAT_LOCOPT"), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(calls, "MMAT_CALLS"), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_CALLS")

    rewrites = [
        m for m in view.mappings if m.status is FactStatus.STATE_CONST_REWRITTEN
    ]
    assert rewrites == []


def test_state_write_anchor_absent_at_later_maturity_emits_identity_lost() -> None:
    locopt = _MATURITY_LOCOPT
    glbopt1 = _MATURITY_GLBOPT1

    class _Pre:
        name = "state-write-pre-absent"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({locopt})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=88:insn=1:ea=0x88:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=88,
                    instruction_ea=0x88,
                    state_const=0xDEADBEEF,
                ),
            )

    class _Post:
        name = "state-write-post-absent"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({glbopt1})

        def collect(self, target, *, func_ea, maturity, phase):
            return ()

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Pre())
    runtime.register(_Post())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(locopt, "MMAT_LOCOPT"), phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(glbopt1, "MMAT_GLBOPT1"), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_GLBOPT1")

    lost = [m for m in view.mappings if m.status is FactStatus.IDENTITY_LOST]
    assert len(lost) == 1
    assert lost[0].payload["block_serial"] == 88
    assert lost[0].payload["original_state_const"] == 0xDEADBEEF


def test_validated_fact_view_state_write_anchors_for_block() -> None:
    locopt = _MATURITY_LOCOPT

    class _Pre:
        name = "state-write-pre-view"
        fact_kinds = frozenset({"StateWriteAnchorFact"})
        maturities = frozenset({locopt})

        def collect(self, target, *, func_ea, maturity, phase):
            return (
                _state_write_obs(
                    fact_id="state_write_anchor:blk=100:insn=0:ea=0x100:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=100,
                    instruction_ea=0x100,
                    state_const=0x5A21D9DB,
                ),
                _state_write_obs(
                    fact_id="state_write_anchor:blk=200:insn=0:ea=0x200:stkoff=0x3c",
                    maturity="MMAT_LOCOPT",
                    block_serial=200,
                    instruction_ea=0x200,
                    state_const=0x432DC789,
                ),
            )

    configure_settings(fact_lifecycle=True)
    runtime = FactLifecycleRuntime()
    runtime.register(_Pre())

    runtime.capture(object(), func_ea=0x401000, provider_phase=_phase(locopt, "MMAT_LOCOPT"), phase="pre_d810")
    view = runtime.validated_view(0x401000, "MMAT_LOCOPT")

    blk100 = view.state_write_anchors_for_block(100)
    blk200 = view.state_write_anchors_for_block(200)
    blk999 = view.state_write_anchors_for_block(999)
    assert len(blk100) == 1
    assert blk100[0].payload["state_const"] == 0x5A21D9DB
    assert len(blk200) == 1
    assert blk200[0].payload["state_const"] == 0x432DC789
    assert blk999 == ()


def test_capture_does_not_dedupe_before_snapshot_backed_capture() -> None:
    configure_settings(fact_lifecycle=True)
    calls = []
    runtime = FactLifecycleRuntime(
        persistence_callback=lambda *args: calls.append(args)
    )
    runtime.register(_Collector())

    no_snapshot = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="instruction_pre_d810",
    )
    with_snapshot = runtime.capture(
        object(),
        func_ea=0x401000,
        provider_phase=_phase(1),
        phase="pre_d810",
        snapshot=_TEST_REF,
    )

    assert no_snapshot.invoked is True
    assert with_snapshot.invoked is True
    assert len(calls) == 1
