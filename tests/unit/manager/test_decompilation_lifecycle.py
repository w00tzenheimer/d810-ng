"""Unit tests for manager-owned decompilation lifecycle coordination."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
    NativePreanalysisFacts,
)
from d810.analyses.control_flow.detached_handler_island import (
    DetachedSnippetBoundaryPorts,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    PortableStateWriteRouteEvidence,
)
from d810.analyses.control_flow.native_semantic_closure import NativeBlock, NativeCfg
from d810.core.native_preanalysis_key import NativePreanalysisKeyMismatch
from d810.core.input_identity_attestation import (
    InputIdentityRecoveryStatus,
    InputIdentityResolution,
)
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.manager.decompilation_lifecycle import (
    AttestedExternalOracleGate,
    DecompilationLifecycleCoordinator,
    FlowgraphReadyPayload,
)
import d810.manager.decompilation_lifecycle as decompilation_lifecycle
from tests.native_preanalysis import make_native_key

NATIVE_KEY = make_native_key()


class _PreanalysisRuntime:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self._calls = calls

    def begin_session(self, event: object) -> None:
        self._calls.append(("preanalysis.reset", event.function_ea))

    def capture_flowgraph(
        self,
        flow_graph: object,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
        snapshot: object | None,
    ) -> None:
        self._calls.append(("phase.flowgraph", (flow_graph, func_ea, provider_phase)))
        self._calls.append(
            (
                "preanalysis.capture",
                (flow_graph, func_ea, provider_phase, "pre_d810", snapshot),
            )
        )

    def capture_ctree(
        self,
        cfunc: object,
        *,
        func_ea: int,
        provider_phase: ProviderPhaseSnapshot,
    ) -> None:
        self._calls.append(("phase.ctree", (cfunc, func_ea, provider_phase)))

    def finish_session(self, event: object) -> None:
        self._calls.append(("preanalysis.finish", event.function_ea))


class _AnalysisRuntime:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self._calls = calls
        self.reset_result = True
        self.hints: object | None = None

    def begin_session(
        self,
        event: object,
        *,
        preserve_active_session: bool = False,
    ) -> bool:
        self._calls.append(
            ("runtime.reset", (event.function_ea, preserve_active_session))
        )
        return self.reset_result

    def analyze(self, func_ea: int) -> object | None:
        self._calls.append(("runtime.analyze", func_ea))
        return self.hints

    def record_execution_scope_outcome(
        self,
        *,
        func_ea: int,
        hints: object,
        apply_result: object,
        source: str,
    ) -> None:
        self._calls.append(
            ("runtime.execution-scope-outcome", (func_ea, hints, apply_result, source))
        )

    def finish_session(
        self,
        event: object,
        *,
        resume_event: object | None = None,
    ) -> None:
        del event
        self._calls.append(
            (
                "runtime.finish",
                None if resume_event is None else resume_event.function_ea,
            )
        )


class _ExecutionScopeService:
    def __init__(self, calls: list[tuple[str, object]]) -> None:
        self._calls = calls

    def clear_hint_state(self, func_ea: int) -> None:
        self._calls.append(("execution-scope.clear", func_ea))

    def apply_hints(self, hints: object) -> str:
        self._calls.append(("execution-scope.apply", hints))
        return "applied"


def _coordinator(
    calls: list[tuple[str, object]],
) -> tuple[DecompilationLifecycleCoordinator, _AnalysisRuntime]:
    runtime = _AnalysisRuntime(calls)
    return (
        DecompilationLifecycleCoordinator(
            preanalysis_runtime=_PreanalysisRuntime(calls),
            analysis_runtime=runtime,
            execution_scope_service=_ExecutionScopeService(calls),
            native_preanalysis_key_provider=lambda _function_ea: NATIVE_KEY,
            mba_mutation_gateway_factory=lambda **kwargs: kwargs,
        ),
        runtime,
    )


def _flowgraph_payload(
    *,
    flow_graph: object = "flow-graph",
    func_ea: int = 0x401000,
    snapshot: object | None = None,
) -> FlowgraphReadyPayload:
    return FlowgraphReadyPayload(
        flow_graph=flow_graph,
        func_ea=func_ea,
        provider_phase=ProviderPhaseSnapshot(
            provider_name="hexrays_microcode",
            provider_level=5,
            friendly_provider_level="MMAT_GLBOPT1",
        ),
        snapshot=snapshot,
    )


def _native_facts(*, key=NATIVE_KEY, blocks=(), transfers=()) -> NativePreanalysisFacts:
    return NativePreanalysisFacts(
        key=key,
        native_cfg=NativeCfg({block.start_ea: block for block in blocks}),
        semantic_closure=None,
        transfers=transfers,
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )


@pytest.mark.parametrize(
    "method_name",
    (
        "mark_normalization_staged",
        "mark_normalization_validated",
        "mark_normalization_published_and_postvalidated",
        "mark_semantic_fragment_staged",
        "mark_semantic_fragment_validated",
        "mark_semantic_fragment_published_and_postvalidated",
        "mark_receipt_committed",
    ),
)
def test_coordinator_has_no_gateway_owned_lifecycle_transition_surface(
    method_name: str,
) -> None:
    coordinator, _runtime = _coordinator([])

    assert not hasattr(coordinator, method_name)


def test_native_fact_session_api_is_idempotent_and_generation_aware() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    session, created = coordinator.ensure(
        NATIVE_KEY,
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    same, created_again = coordinator.ensure(
        NATIVE_KEY,
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    assert created_again is False
    assert same is session
    assert coordinator.get(NATIVE_KEY) is session

    empty = _native_facts()
    assert coordinator.merge_facts(NATIVE_KEY, empty) is True
    assert coordinator.merge_facts(NATIVE_KEY, _native_facts()) is False
    state = session.native_preanalysis
    assert state.evidence_generation == 1
    assert state._fragment_publication_mark_normalization_staged() is True
    assert state._fragment_publication_mark_normalization_validated() is True
    assert (
        state._fragment_publication_mark_normalization_published_and_postvalidated()
        is True
    )
    assert (
        state._fragment_publication_mark_normalization_published_and_postvalidated()
        is False
    )
    assert state.canonical_semantic_plan_generation is None

    changed = _native_facts(blocks=(NativeBlock(0x401000, 0x401010),))
    assert coordinator.merge_facts(NATIVE_KEY, changed) is True
    assert session.native_preanalysis.evidence_generation == 2


def test_coordinator_owns_canonical_semantic_publication_lifecycle() -> None:
    coordinator, _runtime = _coordinator([])
    session, _created = coordinator.ensure(
        NATIVE_KEY,
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    assert coordinator.merge_facts(NATIVE_KEY, _native_facts())
    state = session.native_preanalysis
    assert state._fragment_publication_mark_normalization_staged()
    assert state._fragment_publication_mark_normalization_validated()
    assert state._fragment_publication_mark_normalization_published_and_postvalidated()

    with pytest.raises(ValueError, match="lifecycle evidence epoch mismatch"):
        coordinator.mark_canonical_semantic_plan_ready(NATIVE_KEY, 2)

    assert coordinator.mark_canonical_semantic_plan_ready(NATIVE_KEY, 1)
    assert state._fragment_publication_mark_semantic_fragment_staged()
    assert state._fragment_publication_mark_semantic_fragment_validated()
    assert (
        state._fragment_publication_mark_semantic_fragment_published_and_postvalidated()
    )
    assert state._fragment_publication_mark_receipt_committed()
    assert state.receipt_committed_generation == 1


def test_native_fact_session_api_rejects_key_mismatch() -> None:
    coordinator, _runtime = _coordinator([])
    coordinator.ensure(
        NATIVE_KEY,
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    other = make_native_key(profile_fingerprint="sha256:test-profile-b")

    with pytest.raises(NativePreanalysisKeyMismatch):
        coordinator.merge_facts(NATIVE_KEY, _native_facts(key=other))


def test_native_fact_finish_releases_live_indexes_and_attachments() -> None:
    coordinator, _runtime = _coordinator([])
    session, _created = coordinator.ensure(
        NATIVE_KEY,
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    released: list[bool] = []
    session.current_mba_identity_index = object()
    session.resolver_attachment = type(
        "Attachment",
        (),
        {"release_live_bindings": lambda self: released.append(True)},
    )()

    coordinator.finish(NATIVE_KEY)

    assert coordinator.get(NATIVE_KEY) is None
    assert session.current_mba_identity_index is None
    assert session.resolver_attachment is None
    assert released == [True]


def test_native_fact_session_api_preserves_nested_owners() -> None:
    parent_key = NATIVE_KEY
    child_key = make_native_key(
        function_rva=0x2000,
        function_fingerprint="sha256:test-function-b",
    )
    keys = {0x401000: parent_key, 0x402000: child_key}
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=None,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=keys.__getitem__,
    )

    parent, _created = coordinator.ensure(
        parent_key,
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    child, _created = coordinator.ensure(
        child_key,
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    with pytest.raises(RuntimeError, match="beneath another active owner"):
        coordinator.finish(parent_key)
    coordinator.finish(child_key)
    assert coordinator.get(child_key) is None
    assert coordinator.get(parent_key) is parent
    coordinator.finish(parent_key)
    assert coordinator.get(parent_key) is None
    assert child is not parent


def test_ensure_capture_analyze_and_finish_preserve_lifecycle_order() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, runtime = _coordinator(calls)
    runtime.hints = "hints"

    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))
    coordinator.analyze_current_function(function_ea=0x401000, source="instruction")
    result = coordinator.finish_hexrays_session()

    assert session.function_ea == 0x401000
    assert created is True
    assert session.top_level_epoch == 1
    assert result is None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("execution-scope.clear", 0x401000),
        (
            "phase.flowgraph",
            ("flow-graph", 0x401000, _flowgraph_payload().provider_phase),
        ),
        (
            "preanalysis.capture",
            (
                "flow-graph",
                0x401000,
                _flowgraph_payload().provider_phase,
                "pre_d810",
                "snapshot",
            ),
        ),
        ("runtime.analyze", 0x401000),
        ("execution-scope.apply", "hints"),
        (
            "runtime.execution-scope-outcome",
            (0x401000, "hints", "applied", "instruction"),
        ),
        ("preanalysis.finish", 0x401000),
        ("runtime.finish", None),
    ]
    assert coordinator.current_session(0x401000) is None


def test_repeated_ensure_for_same_top_level_decompilation_reuses_epoch() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    first, first_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    repeated, repeated_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert repeated is first
    assert first_created is True
    assert repeated_created is False
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("execution-scope.clear", 0x401000),
    ]


def test_new_session_initializes_injected_resolver_attachment_exactly_once() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    initialized: list[object] = []

    def initialize(session: object) -> object:
        initialized.append(session)
        return type(
            "ResolverAttachment",
            (),
            {
                "native_preanalysis": session.native_preanalysis,
                "native_key": session.native_key,
                "indirect_label_materialized": False,
                "indirect_dispatcher_materialized": False,
                "invalidate_current_mba_binding": lambda self: None,
                "release_live_bindings": lambda self: None,
            },
        )()

    coordinator.resolver_attachment_initializer = initialize

    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    repeated, repeated_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    assert repeated_created is False
    assert repeated is session
    assert initialized == [session]


def test_lifecycle_context_owns_portable_preanalysis_state_directly() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert session.native_preanalysis.evidence_generation == 0
    assert created is True
    assert (
        session.native_preanalysis.normalization_published_postvalidated_generation
        is None
    )
    assert session.resolver_attachment is None


def test_rebound_bootstrap_fact_is_published_once_on_a_real_snapshot(
    monkeypatch,
) -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
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
    assert session.native_preanalysis.merge_bootstrap_route(route)
    assert session.native_preanalysis.mark_bootstrap_route_rebound(route)
    published: list[object] = []
    import d810.core.observability as observability

    monkeypatch.setattr(observability, "emit", published.append)

    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))
    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))

    assert len(published) == 1
    event = published[0]
    assert event.observations[0].kind == "PreoptBootstrapRouteFact"
    assert event.observations[0].source_block is None
    assert event.observations[0].payload == {
        "source_ea": "0x401020",
        "state": "0x12345678",
        "handler_ea": "0x401100",
        "generation": 1,
        "proof_kind": "static_native",
        "rebound": True,
    }


def test_state_write_route_inventory_is_published_once_on_a_real_snapshot(
    monkeypatch,
) -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401020, 0x401021),), native_key=NATIVE_KEY
    )
    delivery = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401030, 0x401031),), native_key=NATIVE_KEY
    )
    target = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x401100, 0x401101),), native_key=NATIVE_KEY
    )
    route = PortableStateWriteRouteEvidence(
        write_identity=source,
        delivery_identity=delivery,
        source_write_ea=0x401020,
        delivery_ea=0x401030,
        delivery_region_start_ea=0x401030,
        delivery_region_end_ea=0x401035,
        corridor_instruction_eas=(0x401020, 0x401030),
        state_var_reg=20,
        state_constant=0x12345678,
        target_identity=target,
        target_ea=0x401100,
        authority_transfer_ea=None,
        preserved_call_instruction_eas=(),
    )
    assert session.native_preanalysis.merge_state_write_routes(NATIVE_KEY, (route,))
    published: list[object] = []
    import d810.core.observability as observability

    monkeypatch.setattr(observability, "emit", published.append)

    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))
    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))

    assert len(published) == 1
    event = published[0]
    assert len(event.observations) == 1
    observation = event.observations[0]
    assert observation.kind == "StateWriteRouteEvidenceFact"
    assert observation.source_ea == 0x401020
    assert observation.payload == {
        "generation": 1,
        "proof_kind": "state_assignment",
        "delivery_kind": "dispatcher",
        "source_write_ea": "0x401020",
        "delivery_ea": "0x401030",
        "delivery_region_start_ea": "0x401030",
        "delivery_region_end_ea": "0x401035",
        "corridor_instruction_eas": ["0x401020", "0x401030"],
        "state_var_reg": 20,
        "state_constant": "0x12345678",
        "target_ea": "0x401100",
        "authority_transfer_ea": None,
        "preserved_call_instruction_eas": [],
        "inventory_revision": 1,
    }


def test_materialized_transfer_inventory_is_published_once_per_generation(
    monkeypatch,
) -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x401020,
        source_block_ea=0x401010,
        materialized_anchor_eas=(0x401020,),
        target_eas=(0x401100, 0x401200),
        true_target_ea=0x401100,
        false_target_ea=0x401200,
        predicate_true_state=0x11111111,
        predicate_false_state=0x22222222,
        selector_state_var_reg=20,
        resolver_kind="static_conditional_state_choice",
    )
    assert session.native_preanalysis.merge_native_facts(
        NATIVE_KEY,
        native_cfg=NativeCfg({}),
        transfers=(transfer,),
        boundary_ports=DetachedSnippetBoundaryPorts((), ()),
    )
    published: list[object] = []
    import d810.core.observability as observability

    monkeypatch.setattr(observability, "emit", published.append)

    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))
    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="snapshot"))

    assert len(published) == 1
    event = published[0]
    assert len(event.observations) == 1
    observation = event.observations[0]
    assert observation.kind == "ResolverTransferEvidenceFact"
    assert observation.source_block is None
    assert observation.payload["generation"] == 1
    assert observation.payload["inventory_revision"] == 1
    assert observation.payload["source_jmp_ea"] == "0x401020"
    assert observation.payload["target_eas"] == ["0x401100", "0x401200"]
    assert observation.payload["predicate_true_state"] == "0x11111111"
    assert observation.payload["predicate_false_state"] == "0x22222222"

    later_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x401030,
        source_block_ea=0x401030,
        materialized_anchor_eas=(),
        target_eas=(0x401300,),
        resolver_kind="static_handler_entry_route",
    )
    assert session.native_preanalysis.merge_materialized_transfers(
        NATIVE_KEY,
        (later_transfer,),
    )
    assert session.native_preanalysis.evidence_generation == 1

    coordinator.capture_flowgraph(_flowgraph_payload(snapshot="later-snapshot"))

    assert len(published) == 2
    later_event = published[1]
    assert len(later_event.observations) == 2
    assert {
        item.payload["inventory_revision"] for item in later_event.observations
    } == {2}


def test_lifecycle_releases_current_mba_identity_index_when_session_finishes() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    current_index = object()

    assert created is True

    coordinator.bind_current_mba_identity_index(
        function_ea=0x401000,
        index=current_index,
    )
    assert session.current_mba_identity_index is current_index
    assert coordinator.finish_hexrays_session() is None
    assert session.current_mba_identity_index is None


def test_flowchart_generation_resets_generated_and_preopt_publication_guards() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.bind_current_mba_identity_index(
        function_ea=0x401000,
        index=object(),
    )
    coordinator.mark_generated_ready_emitted(
        function_ea=0x401000,
        microcode_modified=False,
    )

    # A graph-free GENERATED identity index is maturity-local even when no
    # listener writes.  It must not become final-binding authority for a later
    # PREOPT/LOCOPT transaction.
    assert session.current_mba_identity_index is None

    coordinator.mark_preopt_ready_emitted(
        function_ea=0x401000,
        microcode_modified=True,
    )

    assert session.current_mba_identity_index is None
    assert coordinator.generated_ready_was_emitted(function_ea=0x401000)
    assert coordinator.preopt_ready_was_emitted(function_ea=0x401000)
    coordinator.mark_preopt_ready_emitted(
        function_ea=0x401000,
        microcode_modified=True,
    )

    coordinator.begin_current_mba_generation(function_ea=0x401000)

    assert session.current_mba_identity_index is None
    assert coordinator.current_mba_generation(function_ea=0x401000) == 1
    assert not coordinator.generated_ready_was_emitted(function_ea=0x401000)
    assert not coordinator.preopt_ready_was_emitted(function_ea=0x401000)

    coordinator.mark_generated_ready_emitted(
        function_ea=0x401000,
        microcode_modified=True,
    )

    assert session.current_mba_identity_index is None
    assert coordinator.generated_ready_was_emitted(function_ea=0x401000)

    coordinator.bind_current_mba_identity_index(
        function_ea=0x401000,
        index=object(),
    )
    coordinator.mark_preopt_ready_emitted(
        function_ea=0x401000,
        microcode_modified=False,
    )

    assert coordinator.preopt_ready_was_emitted(function_ea=0x401000)

    coordinator.begin_current_mba_generation(function_ea=0x401000)

    assert coordinator.current_mba_generation(function_ea=0x401000) == 2
    assert not coordinator.generated_ready_was_emitted(function_ea=0x401000)
    assert not coordinator.preopt_ready_was_emitted(function_ea=0x401000)


def test_session_gateway_reuses_the_active_current_mba_identity_index() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    index = type("_Index", (), {"generation": 3})()
    coordinator.bind_current_mba_identity_index(
        function_ea=0x401000,
        index=index,
    )

    gateway = coordinator.new_current_mba_mutation_gateway(
        function_ea=0x401000,
        maturity=4,
    )

    assert gateway == {
        "session": session,
        "identity_index": index,
        "maturity": 4,
        "event_emitter": None,
    }
    assert session.current_mba_identity_index is index


def test_session_materializer_factory_is_scoped_to_the_active_function() -> None:
    calls: list[dict[str, object]] = []
    materializer = object()
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=None,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=lambda _function_ea: NATIVE_KEY,
        semantic_native_body_materializer_factory=lambda **kwargs: (
            calls.append(kwargs) or materializer
        ),
    )
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    mba = object()

    assert (
        coordinator.new_semantic_native_body_materializer(
            function_ea=0x401000,
            mba=mba,
        )
        is materializer
    )
    assert calls == [{"session": session, "mba": mba}]
    assert (
        coordinator.new_semantic_native_body_materializer(
            function_ea=0x402000,
            mba=mba,
        )
        is None
    )
    assert calls == [{"session": session, "mba": mba}]


def test_nested_different_function_gets_a_new_epoch_and_restores_parent() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    outer, outer_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    inner, inner_created = coordinator.ensure_hexrays_session(
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    assert outer.top_level_epoch == 1
    assert inner.top_level_epoch == 1
    assert outer_created is True
    assert inner_created is True
    assert coordinator.current_session(0x401000) is outer
    assert coordinator.current_session(0x402000) is inner

    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is outer
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("execution-scope.clear", 0x401000),
        ("preanalysis.reset", 0x402000),
        ("runtime.reset", (0x402000, True)),
        ("execution-scope.clear", 0x402000),
        ("preanalysis.finish", 0x402000),
        ("runtime.finish", 0x401000),
        ("preanalysis.finish", 0x401000),
        ("runtime.finish", None),
    ]


def test_reentry_below_a_nested_child_reuses_parent_without_finishing_it() -> None:
    """A parent callback resumed during a child decompile keeps its evidence."""
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    parent, parent_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    child, child_created = coordinator.ensure_hexrays_session(
        function_ea=0x402000,
        database_identity="sample.i64",
    )

    resumed_parent, resumed_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert parent_created is True
    assert child_created is True
    assert resumed_parent is parent
    assert resumed_created is False
    assert coordinator.current_session(0x401000) is parent
    assert coordinator.current_session(0x402000) is child

    # The structural callback for the temporary reentry must not finish the
    # parent session or the nested child beneath it.
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is parent
    assert coordinator.current_session(0x402000) is child

    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x402000) is None
    assert coordinator.current_session(0x401000) is parent
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("execution-scope.clear", 0x401000),
        ("preanalysis.reset", 0x402000),
        ("runtime.reset", (0x402000, True)),
        ("execution-scope.clear", 0x402000),
        ("preanalysis.finish", 0x402000),
        ("runtime.finish", 0x401000),
        ("preanalysis.finish", 0x401000),
        ("runtime.finish", None),
    ]


def test_native_preanalysis_reserves_the_owner_across_an_internal_callback() -> None:
    """An internal preflight decompile cannot finish its caller's session."""
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    coordinator.begin_native_preanalysis(session)
    callback_session, callback_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
        callback_entry_ea=0x401020,
    )

    assert callback_session is session
    assert callback_created is False
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is session

    coordinator.finish_native_preanalysis(session)
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None
    assert calls == [
        ("preanalysis.reset", 0x401000),
        ("runtime.reset", (0x401000, False)),
        ("execution-scope.clear", 0x401000),
        ("preanalysis.finish", 0x401000),
        ("runtime.finish", None),
    ]


def test_native_preanalysis_redo_reuses_the_active_callback_activation() -> None:
    """MERR_REDO can emit a second prolog but only one structural finish."""
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    coordinator.begin_native_preanalysis(session)
    first, first_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
        callback_entry_ea=0x401020,
    )
    restarted, restarted_created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
        callback_entry_ea=0x401000,
    )

    assert first is session
    assert restarted is session
    assert first_created is False
    assert restarted_created is False
    assert coordinator.finish_hexrays_session() is None
    coordinator.finish_native_preanalysis(session)

    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None


def test_pending_generated_restart_retains_owner_until_flowchart_consumes_it() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)
    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    session.native_preanalysis.evidence_generation = 2
    assert session.native_preanalysis.request_generated_restart(
        evidence_family="test_evidence",
        reason="test staged a generated restart",
    )

    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is session
    assert coordinator.has_pending_generated_restart(0x401000)

    assert session.native_preanalysis.consume_generated_restart()
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None


def test_analysis_without_hints_does_not_apply_or_record_execution_scope_outcome() -> None:
    calls: list[tuple[str, object]] = []
    coordinator, _runtime = _coordinator(calls)

    coordinator.analyze_current_function(function_ea=0x401000, source="ctree")

    assert calls == [("runtime.analyze", 0x401000)]


def _local_only_resolution() -> InputIdentityResolution:
    return InputIdentityResolution(
        status=InputIdentityRecoveryStatus.RECOVERED_LOCAL_ONLY,
        input_identity="sha256:" + ("a" * 64),
        provenance="recovered_from_d810_attestation",
        external_evidence_allowed=False,
        database_uuid="attested-db",
    )


def test_attested_local_identity_blocks_external_oracle_calls() -> None:
    calls: list[str] = []

    class _Oracle:
        def reference_oracle_scope_for(self, *_args):
            calls.append("scope")
            return object()

        def reference_oracle_for(self, *_args):
            calls.append("anchors")
            return object()

    gate = AttestedExternalOracleGate(
        delegate=_Oracle(),
        identity_resolution=_local_only_resolution(),
    )

    assert gate.reference_oracle_scope_for(0x401000, NATIVE_KEY) is None
    assert gate.reference_oracle_for(0x401000, NATIVE_KEY, (0x401020,)) is None
    assert calls == []


def test_file_verified_identity_delegates_external_oracle_calls() -> None:
    calls: list[str] = []

    class _Oracle:
        def reference_oracle_scope_for(self, *_args):
            calls.append("scope")
            return "scope-result"

        def reference_oracle_for(self, *_args):
            calls.append("anchors")
            return "anchor-result"

    gate = AttestedExternalOracleGate(
        delegate=_Oracle(),
        identity_resolution=InputIdentityResolution(
            status=InputIdentityRecoveryStatus.RECOVERED_FILE_HASH_VERIFIED,
            input_identity="sha256:" + ("b" * 64),
            provenance="recovered_from_d810_attestation",
            external_evidence_allowed=True,
            database_uuid="attested-db",
        ),
    )

    assert gate.reference_oracle_scope_for(0x401000, NATIVE_KEY) == "scope-result"
    assert (
        gate.reference_oracle_for(0x401000, NATIVE_KEY, (0x401020,))
        == "anchor-result"
    )
    assert calls == ["scope", "anchors"]


def test_missing_identity_logs_warning_and_abstains_before_session_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        decompilation_lifecycle,
        "logger",
        SimpleNamespace(warning=lambda *args: warnings.append(args)),
    )
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=None,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=lambda _function_ea: SimpleNamespace(
            native_key=None,
            identity_resolution=InputIdentityResolution(
                status=InputIdentityRecoveryStatus.RECOVERY_DISABLED,
                input_identity=None,
                provenance=None,
                external_evidence_allowed=False,
            ),
        ),
    )

    with pytest.raises(ValueError, match="input identity unavailable"):
        coordinator.ensure_hexrays_session(
            function_ea=0x401000,
            database_identity="sample.i64",
        )

    assert warnings[0][0].startswith("D810 native mutation abstained")
    assert coordinator.current_session(0x401000) is None


def test_lifecycle_attaches_extended_identity_resolution_from_provider() -> None:
    resolution = _local_only_resolution()
    attested_key = make_native_key(input_identity=resolution.input_identity)
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=None,
        analysis_runtime=None,
        execution_scope_service=None,
        native_preanalysis_key_provider=lambda _function_ea: SimpleNamespace(
            native_key=attested_key,
            identity_resolution=resolution,
        ),
    )

    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    assert session.native_key is attested_key
    assert session.input_identity_resolution is resolution
