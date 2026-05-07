"""Tests for the maturity fact runtime."""
from __future__ import annotations

from d810.core.settings import configure_settings, reset_settings
from d810.recon.facts import (
    FactCollectionResult,
    FactLifecycleRuntime,
    FactMapping,
    FactObservation,
    FactStatus,
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
        diag_conn, snapshot_id, func_ea, observations, mappings, conflicts
    ) -> None:
        calls.append((diag_conn, snapshot_id, func_ea, observations, mappings, conflicts))

    runtime = FactLifecycleRuntime(persistence_callback=_persist)
    runtime.register(_Collector())
    diag_conn = object()

    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        maturity=1,
        phase="pre_d810",
        snapshot_id=7,
        diag_conn=diag_conn,
    )

    assert summary.invoked is True
    assert summary.observation_count == 1
    assert len(calls) == 1
    assert calls[0][0] is diag_conn
    assert calls[0][1] == 7
    assert calls[0][2] == 0x401000
    assert calls[0][3][0].fact_id == "induction:blk10"
    assert calls[0][4] == ()
    assert calls[0][5] == ()


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
        maturity=4,
        snapshot_id=9,
        diag_conn=object(),
    )

    assert summary.mapping_count == 1
    assert calls[0][4][0].source_fact_id == "induction:blk10"


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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    active_before = runtime.validated_view(0x401000, 1)
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=3, phase="pre_d810")

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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
        snapshot_id=8,
        diag_conn=object(),
    )
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert summary.conflict_count == 1
    assert len(view.mappings) == 1
    mapping = view.mappings[0]
    assert mapping.status is FactStatus.CONTRADICTED
    assert mapping.source_fact_id == "induction:old"
    assert mapping.target_fact_id is None
    conflicts = calls[0][5]
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
        maturity=1,
        phase="pre_d810",
        snapshot_id=8,
        diag_conn=object(),
    )

    assert summary.conflict_count == 1
    conflicts = calls[0][5]
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    summary = runtime.capture(
        object(),
        func_ea=0x401000,
        maturity=2,
        phase="pre_d810",
        snapshot_id=8,
        diag_conn=object(),
    )
    view = runtime.validated_view(0x401000, "MMAT_2")

    assert summary.conflict_count == 1
    assert len(view.mappings) == 1
    assert view.mappings[0].status is FactStatus.CONTRADICTED
    assert view.mappings[0].source_fact_id == "induction:old"
    assert view.mappings[0].target_fact_id is None
    assert {obs.fact_id for obs in view.active_observations} == {"induction:new"}
    conflicts = calls[0][5]
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
    first_mapping_count = len(runtime.validated_view(0x401000, "MMAT_2").mappings)
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="post_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(_Target(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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

    runtime.capture(object(), func_ea=0x401000, maturity=1, phase="pre_d810")
    runtime.capture(object(), func_ea=0x401000, maturity=2, phase="pre_d810")
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
        maturity=1,
        phase="instruction_pre_d810",
    )
    with_snapshot = runtime.capture(
        object(),
        func_ea=0x401000,
        maturity=1,
        phase="pre_d810",
        snapshot_id=8,
        diag_conn=object(),
    )

    assert no_snapshot.invoked is True
    assert with_snapshot.invoked is True
    assert len(calls) == 1
