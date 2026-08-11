"""Runtime-layer PREOPT adapter for manager-owned normalization."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.frontend_normalization import (
    FrontendNormalizationEvidenceRejected,
)
from d810.core.observability import subscribe, unsubscribe
from d810.core.observability_events import (
    FrontendNormalizationPlanIntentObserved,
    LifecycleEventObserved,
)
from d810.core.fragment_authority import NormalizationWorkItemAuthority
from d810.ir.block_identity import (
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.manager.decompilation_lifecycle import DecompilationSessionContext
from d810.manager.frontend_normalization import (
    FrontendNormalizationPublicationError,
    FrontendNormalizationRunResult,
)
from d810.manager import hexrays_frontend_normalization as live_normalization
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    resolver_session_state,
)
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentOperation,
    FragmentPlan,
    FragmentPlanRejected,
    FragmentPublicationPurpose,
    FragmentWorkItemScope,
)
from d810.transforms.frontend_normalization import (
    FrontendNormalizationGenerationPlan,
)
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


def _record_complete_plan_intent(session: DecompilationSessionContext) -> FragmentPlan:
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1000, 0x1001),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1000,),
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x1010, 0x1011),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x1010,),
    )
    original = FragmentBlock(
        block_id="source.original",
        role=FragmentBlockRole.ORIGINAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x1000,
        stable_identity=source_identity,
    )
    replacement = FragmentBlock(
        block_id="source.replacement",
        role=FragmentBlockRole.REPLACEMENT,
        materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
        semantic_anchor_ea=0x1000,
        stable_identity=source_identity,
        replaces_block_id=original.block_id,
    )
    target = FragmentBlock(
        block_id="target",
        role=FragmentBlockRole.EXTERNAL,
        materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
        semantic_anchor_ea=0x1010,
        stable_identity=target_identity,
    )
    plan = FragmentPlan(
        plan_id="frontend-normalization:0x1000:g3",
        atomic_group_id="frontend-normalization:g3",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=NATIVE_KEY,
        blocks=(original, replacement, target),
        roots=(replacement.block_id,),
        owned_originals=(original.block_id,),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="native-indirect-transfer@0x1000",
                source_block_id=replacement.block_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id=target.block_id,
                    ),
                ),
            ),
        ),
        work_item_scope=FragmentWorkItemScope(
            work_item_id="frontend-normalization:0x1000:g3:complete",
            selected_obligation_ids=("native-indirect-transfer@0x1000",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
    )
    work_item_plan_id = "frontend-normalization:0x1000:g3:root@0x1000"
    work_item_plan = replace(
        plan,
        plan_id=work_item_plan_id,
        atomic_group_id="frontend-normalization:g3:root@0x1000",
        work_item_scope=FragmentWorkItemScope(
            work_item_id=work_item_plan_id,
            selected_obligation_ids=("native-indirect-transfer@0x1000",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
    )
    session.frontend_normalization_plan_authority.record_receipted_generation(
        FrontendNormalizationGenerationPlan(
            complete_plan=plan,
            work_item_plan=work_item_plan,
        ),
        authority=NormalizationWorkItemAuthority(
            evidence_generation=3,
            publication_revision=1,
            source_plan_id=plan.plan_id,
            source_atomic_group_id=plan.atomic_group_id,
            work_item_id=work_item_plan_id,
            published_operation_ids=("native-indirect-transfer@0x1000",),
            selected_obligation_ids=("native-indirect-transfer@0x1000",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
    )
    return plan


def test_live_adapter_reports_only_receipt_backed_pipeline_result(
    monkeypatch,
) -> None:
    session = _session()
    reference_oracle_provider = object()
    resolver_session_state(
        session
    ).semantic_route_reference_oracle_provider = reference_oracle_provider
    session.native_preanalysis.evidence_generation = 3
    session.native_preanalysis.portable_evidence_ready_generation = 3
    _record_complete_plan_intent(session)
    mba = SimpleNamespace(
        this=0x5678,
        qty=0,
        get_mblock=lambda _serial: None,
    )
    gateway = object()
    materializer = object()
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
        "semantic_native_body_materializer": materializer,
    }

    live_normalization.run_live_frontend_normalization(
        function_ea=0x1000,
        mba=mba,
        decision=decision,
    )

    assert captured["backend_args"] == {
        "mutation_gateway": gateway,
        "semantic_native_body_materializer": materializer,
    }
    pipeline_args = captured["pipeline_args"]
    assert pipeline_args["source"] is source
    assert pipeline_args["backend"] is backend
    assert pipeline_args["lifecycle_state"] is session.native_preanalysis
    assert pipeline_args["native_key"] == NATIVE_KEY
    assert pipeline_args["reference_oracle_provider"] is reference_oracle_provider
    assert (
        pipeline_args["plan_authority"] is session.frontend_normalization_plan_authority
    )
    assert decision["microcode_modified"] is True
    assert decision["details"] == {
        "frontend_normalization": {
            "authority": "fragment_receipt",
            "published_generation": 3,
            "published_work_item_id": None,
            "remaining_obligation_count": 0,
        }
    }


def test_live_adapter_abstains_without_lifecycle_owned_materializer(
    monkeypatch,
) -> None:
    session = _session()
    gateway = object()
    monkeypatch.setattr(
        live_normalization,
        "_lift_live_function",
        lambda _mba: (_ for _ in ()).throw(
            AssertionError("adapter lifted without its materializer capability")
        ),
    )

    decision = {
        "session": session,
        "mutation_gateway": gateway,
    }
    live_normalization.run_live_frontend_normalization(
        function_ea=0x1000,
        mba=object(),
        decision=decision,
    )

    assert decision == {
        "session": session,
        "mutation_gateway": gateway,
    }


def test_live_adapter_rejects_modified_result_without_complete_plan_intent(
    monkeypatch,
) -> None:
    session = _session()
    session.native_preanalysis.evidence_generation = 3
    session.native_preanalysis.portable_evidence_ready_generation = 3
    mba = SimpleNamespace(this=0x1234)
    monkeypatch.setattr(
        live_normalization,
        "_lift_live_function",
        lambda live_mba: SimpleNamespace(
            flow_graph=GRAPH,
            func_ea=0x1000,
            live_source=live_mba,
        ),
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
            microcode_modified=True,
            published_generation=None,
        ),
    )

    with pytest.raises(
        FrontendNormalizationPublicationError,
        match="lacks receipt-backed complete intent",
    ):
        live_normalization.run_live_frontend_normalization(
            function_ea=0x1000,
            mba=mba,
            decision={
                "session": session,
                "mutation_gateway": object(),
                "semantic_native_body_materializer": object(),
            },
        )


def test_live_adapter_receipts_identity_without_rebinding_producer_callback(
    monkeypatch,
) -> None:
    from d810.hexrays.mutation import detached_handler_island

    session = _session()
    session.native_preanalysis.evidence_generation = 3
    session.native_preanalysis.portable_evidence_ready_generation = 3
    complete_plan = _record_complete_plan_intent(session)
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
    monkeypatch.setattr(
        live_normalization, "_new_live_backend", lambda **_kwargs: backend
    )
    monkeypatch.setattr(
        live_normalization,
        "run_frontend_normalization_pipeline",
        lambda **_kwargs: FrontendNormalizationRunResult(
            graph=GRAPH,
            microcode_modified=True,
            published_generation=None,
        ),
    )

    observed: list[LifecycleEventObserved] = []
    observed_intents: list[FrontendNormalizationPlanIntentObserved] = []
    subscribe(LifecycleEventObserved, observed.append)
    subscribe(FrontendNormalizationPlanIntentObserved, observed_intents.append)
    try:
        live_normalization.run_live_frontend_normalization(
            function_ea=0x1000,
            mba=mba,
            decision={
                "session": session,
                "mutation_gateway": object(),
                "semantic_native_body_materializer": object(),
            },
        )
    finally:
        unsubscribe(LifecycleEventObserved, observed.append)
        unsubscribe(FrontendNormalizationPlanIntentObserved, observed_intents.append)

    assert state.current_mba_token is None
    assert state.current_mba_identity_binding_for(0x1234) is None
    assert state.imported_instruction_origins_for(0x1234) == ()
    assert len(observed) == 1
    assert len(observed_intents) == 1
    intent_event = observed_intents[0]
    identity_event = observed[0]
    assert intent_event.work_item_id == (
        "frontend-normalization:0x1000:g3:root@0x1000"
    )
    assert intent_event.plan_id == complete_plan.plan_id
    assert intent_event.atomic_group_id == complete_plan.atomic_group_id
    assert intent_event.publication_revision == 1
    assert intent_event.block_count == 3
    assert intent_event.operation_count == 1
    assert '"plan_id":"frontend-normalization:0x1000:g3"' in (
        intent_event.complete_plan_json
    )
    assert identity_event.event_kind == "current_mba_import_identity_receipted"
    assert identity_event.payload == {
        "outcome": "receipted",
        "resolver_activation": "not_bound_in_producer_callback",
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
                "native_ranges": [{"start_ea": 0x40A700, "end_ea": 0x40A720}],
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
        "semantic_native_body_materializer": object(),
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
                    "semantic_native_body_materializer": object(),
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
