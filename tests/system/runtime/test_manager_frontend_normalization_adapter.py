"""Runtime-layer PREOPT adapter for manager-owned normalization."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidenceRejected,
)
from d810.core.observability import subscribe, unsubscribe
from d810.core.observability_events import LifecycleEventObserved
from d810.ir.block_identity import (
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.manager.decompilation_lifecycle import DecompilationSessionContext
from d810.manager.frontend_normalization import FrontendNormalizationRunResult
from d810.manager import hexrays_frontend_normalization as live_normalization
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    resolver_session_state,
)
from d810.transforms.fragment_plan import FragmentPlanRejected
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key(function_rva=0x1000)
GRAPH = FlowGraph(
    blocks={
        0: BlockSnapshot(
            serial=0,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0x1000,
            insn_snapshots=(),
        )
    },
    entry_serial=0,
    func_ea=0x1000,
)


def _session() -> DecompilationSessionContext:
    return DecompilationSessionContext(
        function_ea=0x1000,
        database_identity="test",
        top_level_epoch=1,
        native_key=NATIVE_KEY,
    )


def test_live_adapter_reports_only_receipt_backed_pipeline_result(
    monkeypatch,
) -> None:
    session = _session()
    session.native_preanalysis.evidence_generation = 3
    session.native_preanalysis.portable_evidence_ready_generation = 3
    mba = SimpleNamespace(
        this=0x5678,
        qty=0,
        get_mblock=lambda _serial: None,
    )
    gateway = object()
    source = SimpleNamespace(
        flow_graph=GRAPH,
        func_ea=0x1000,
        live_source=mba,
    )
    backend = SimpleNamespace(
        committed_current_mba_identity_binding=lambda: (
            CurrentMbaIdentityBindingSnapshot((), ())
        ),
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        live_normalization,
        "_lift_live_function",
        lambda live_mba: source if live_mba is mba else None,
    )

    def new_backend(**kwargs):
        captured["backend_args"] = kwargs
        return backend

    monkeypatch.setattr(live_normalization, "_new_live_backend", new_backend)

    def run_pipeline(**kwargs):
        captured["pipeline_args"] = kwargs
        return FrontendNormalizationRunResult(
            graph=GRAPH,
            microcode_modified=True,
            published_generation=3,
        )

    monkeypatch.setattr(
        live_normalization,
        "run_frontend_normalization_pipeline",
        run_pipeline,
    )
    decision = {
        "session": session,
        "identity_index": object(),
        "mutation_gateway": gateway,
    }

    live_normalization.run_live_frontend_normalization(
        function_ea=0x1000,
        mba=mba,
        decision=decision,
    )

    assert captured["backend_args"] == {
        "mba": mba,
        "function_ea": 0x1000,
        "mutation_gateway": gateway,
    }
    pipeline_args = captured["pipeline_args"]
    assert pipeline_args["source"] is source
    assert pipeline_args["backend"] is backend
    assert pipeline_args["lifecycle_state"] is session.native_preanalysis
    assert pipeline_args["native_key"] == NATIVE_KEY
    assert decision["microcode_modified"] is True
    assert decision["details"] == {
        "frontend_normalization": {
            "authority": "fragment_receipt",
            "published_generation": 3,
            "published_work_item_id": None,
            "remaining_obligation_count": 0,
        }
    }


def test_live_adapter_binds_committed_import_identity_to_current_mba(
    monkeypatch,
) -> None:
    from d810.hexrays.mutation import detached_handler_island

    session = _session()
    session.native_preanalysis.evidence_generation = 3
    session.native_preanalysis.portable_evidence_ready_generation = 3
    state = resolver_session_state(session)
    mba = SimpleNamespace(this=0x1234)
    imported_origins = (
        (0xFFFFFFFFFFFFFF01, 0x40A70E),
        (0xFFFFFFFFFFFFFF02, 0x40A710),
    )
    imported_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40A700, 0x40A720),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40A70E, 0x40A710),
    )
    imported_binding = CurrentMbaIdentityBindingSnapshot(
        instruction_origins=imported_origins,
        block_bindings=(
            CurrentMbaBlockIdentityBinding(
                stable_identity=imported_identity,
                live_instruction_eas=frozenset(
                    live_ea for live_ea, _native_ea in imported_origins
                ),
            ),
        ),
    )
    monkeypatch.setattr(
        detached_handler_island,
        "imported_detached_snippet_instruction_origins",
        lambda _live_mba: (_ for _ in ()).throw(
            AssertionError("receipt-backed publication must not query legacy origins")
        ),
    )
    monkeypatch.setattr(
        live_normalization,
        "_lift_live_function",
        lambda live_mba: SimpleNamespace(
            flow_graph=GRAPH,
            func_ea=0x1000,
            live_source=live_mba,
        ),
    )
    backend = SimpleNamespace(
        committed_current_mba_identity_binding=lambda: imported_binding,
    )
    monkeypatch.setattr(live_normalization, "_new_live_backend", lambda **_kwargs: backend)
    monkeypatch.setattr(
        live_normalization,
        "run_frontend_normalization_pipeline",
        lambda **_kwargs: FrontendNormalizationRunResult(
            graph=GRAPH,
            microcode_modified=True,
            published_generation=3,
        ),
    )

    observed: list[LifecycleEventObserved] = []
    subscribe(LifecycleEventObserved, observed.append)
    try:
        live_normalization.run_live_frontend_normalization(
            function_ea=0x1000,
            mba=mba,
            decision={
                "session": session,
                "mutation_gateway": object(),
            },
        )
    finally:
        unsubscribe(LifecycleEventObserved, observed.append)

    assert state.current_mba_token == 0x1234
    assert state.current_mba_identity_binding_for(0x1234) is imported_binding
    assert state.imported_instruction_origins_for(0x1234) == imported_origins
    assert len(observed) == 1
    assert observed[0].event_kind == "current_mba_import_identity_bound"
    assert observed[0].payload == {
        "outcome": "bound",
        "origin_count": 2,
        "native_ea_count": 2,
        "native_eas": [0x40A70E, 0x40A710],
        "block_binding_count": 1,
        "block_bindings": [
            {
                "live_instruction_eas": [
                    0xFFFFFFFFFFFFFF01,
                    0xFFFFFFFFFFFFFF02,
                ],
                "exact_instruction_eas": [0x40A70E, 0x40A710],
                "native_ranges": [
                    {"start_ea": 0x40A700, "end_ea": 0x40A720}
                ],
            }
        ],
    }


def test_live_adapter_abstains_without_manager_injected_gateway(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        live_normalization,
        "_lift_live_function",
        lambda _mba: (_ for _ in ()).throw(AssertionError("must not lift")),
    )
    decision = {"session": _session()}

    live_normalization.run_live_frontend_normalization(
        function_ea=0x1000,
        mba=object(),
        decision=decision,
    )

    assert "microcode_modified" not in decision
    assert "details" not in decision


def test_live_adapter_does_not_claim_a_pipeline_noop(monkeypatch) -> None:
    session = _session()
    source = SimpleNamespace(
        flow_graph=GRAPH,
        func_ea=0x1000,
        live_source=object(),
    )
    monkeypatch.setattr(
        live_normalization,
        "_lift_live_function",
        lambda _mba: source,
    )
    monkeypatch.setattr(
        live_normalization,
        "_new_live_backend",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        live_normalization,
        "run_frontend_normalization_pipeline",
        lambda **_kwargs: FrontendNormalizationRunResult(
            graph=GRAPH,
            microcode_modified=False,
            published_generation=None,
        ),
    )
    decision = {
        "session": session,
        "mutation_gateway": object(),
    }

    live_normalization.run_live_frontend_normalization(
        function_ea=0x1000,
        mba=source.live_source,
        decision=decision,
    )

    assert "microcode_modified" not in decision
    assert "details" not in decision


@pytest.mark.parametrize(
    "rejection_type",
    (FrontendNormalizationEvidenceRejected, FragmentPlanRejected),
)
def test_live_adapter_records_planning_rejection_before_failing_open(
    monkeypatch,
    rejection_type,
) -> None:
    session = _session()
    session.native_preanalysis.evidence_generation = 3
    source = SimpleNamespace(
        flow_graph=GRAPH,
        func_ea=0x1000,
        live_source=object(),
    )
    state = resolver_session_state(session)
    monkeypatch.setattr(
        live_normalization,
        "_lift_live_function",
        lambda _mba: source,
    )
    monkeypatch.setattr(
        live_normalization,
        "_new_live_backend",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        live_normalization,
        "run_frontend_normalization_pipeline",
        lambda **_kwargs: (_ for _ in ()).throw(
            rejection_type("original route corridor is not closed")
        ),
    )
    observed: list[LifecycleEventObserved] = []
    subscribe(LifecycleEventObserved, observed.append)
    try:
        with pytest.raises(
            rejection_type,
            match="original route corridor is not closed",
        ):
            live_normalization.run_live_frontend_normalization(
                function_ea=0x1000,
                mba=source.live_source,
                decision={
                    "session": session,
                    "mutation_gateway": object(),
                },
            )
    finally:
        unsubscribe(LifecycleEventObserved, observed.append)

    assert len(observed) == 1
    event = observed[0]
    assert event.session_id == session.identity_key
    assert event.func_ea == 0x1000
    assert event.event_kind == "frontend_normalization_rejected"
    assert event.phase == "frontend_normalization"
    assert event.evidence_generation == 3
    assert event.payload == {
        "outcome": "rejected",
        "reason": "original route corridor is not closed",
    }
    assert state.current_mba_token is None
    assert state.current_mba_identity_binding is None
