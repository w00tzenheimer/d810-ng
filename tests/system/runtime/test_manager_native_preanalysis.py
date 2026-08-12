"""Manager gate for session-owned pre-decompile resolver evidence."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.core.observability_events import (
    IdentityDecisionObserved,
    MutationReceiptObserved,
    SemanticFragmentFailureObserved,
    SemanticFragmentRouteOracleComparedObserved,
)
from d810.core.input_identity_attestation import (
    InputIdentityRecoveryStatus,
    InputIdentityResolution,
)
from d810.core.config import ProjectConfiguration
from d810.core.config_v2_defaults import select_config_v2_default_project
from d810.core.semantic_route_oracle import RouteOracleComparison
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.ir.logical_block_proxy import (
    LogicalBlockVersion,
    LogicalBlockVersionId,
)
from d810.hexrays.mutation.fragment_publication_lifecycle import (
    FragmentPublicationLifecycleAuthority,
)
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationAborted,
    MbaMutationRootPublicationGroup,
    MbaSemanticFragmentRouteOracleCompared,
    StructuralMutationKind,
)
from d810.transforms.detached_route_oracle import DetachedRouteOracleResult
from d810.hexrays.mutation.semantic_fragment_failure import (
    MbaSemanticFragmentFailure,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.block_identity import (
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    MbaBlockHandle,
    NativeEaInterval,
    StableBlockIdentity,
)
from d810.manager.manager import (
    D810Manager,
    _build_current_mba_identity_index,
    _initialize_resolver_attachment,
    _load_semantic_route_reference_oracle_registry,
    _new_current_mba_mutation_gateway,
    _new_semantic_native_body_materializer,
)
from d810.capabilities.frontend_normalization import (
    FrontendNormalizationPreparedBodyCapability,
)
from d810.manager.decompilation_lifecycle import DecompilationSessionContext
from d810.optimizers.microcode.flow.jumps import computed_goto_resolver
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    resolver_session_state,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


def _current_mba_identity_binding() -> CurrentMbaIdentityBindingSnapshot:
    live_ea = 0xFFFFFFFFFFFFFF01
    native_ea = 0x40A70E
    return CurrentMbaIdentityBindingSnapshot(
        instruction_origins=((live_ea, native_ea),),
        block_bindings=(
            CurrentMbaBlockIdentityBinding(
                stable_identity=StableBlockIdentity.from_intervals(
                    (NativeEaInterval(0x40A700, 0x40A720),),
                    native_key=NATIVE_KEY,
                    exact_instruction_eas=(native_ea,),
                ),
                live_instruction_eas=frozenset({live_ea}),
            ),
        ),
    )


def test_resolver_attachment_reads_manager_owned_normalization_plan_port() -> None:
    session = DecompilationSessionContext(
        function_ea=0x40A560,
        database_identity="test",
        top_level_epoch=1,
        native_key=NATIVE_KEY,
    )

    state = _initialize_resolver_attachment(session)

    assert (
        state.frontend_normalization_plan_provider
        is session.frontend_normalization_plan_authority
    )
    assert isinstance(
        state.frontend_normalization_plan_provider,
        FrontendNormalizationPreparedBodyCapability,
    )


def test_resolver_attachment_reads_manager_owned_reference_oracle_port() -> None:
    session = DecompilationSessionContext(
        function_ea=0x40A560,
        database_identity="test",
        top_level_epoch=1,
        native_key=NATIVE_KEY,
    )

    class _ReferenceOracleProvider:
        @staticmethod
        def reference_oracle_scope_for(function_ea, native_key):
            return None

        @staticmethod
        def reference_oracle_for(function_ea, native_key, rewrite_anchor_eas):
            return None

    provider = _ReferenceOracleProvider()
    state = _initialize_resolver_attachment(
        session,
        semantic_route_reference_oracle_provider=provider,
    )

    assert state.semantic_route_reference_oracle_provider is provider


def test_resolver_attachment_gates_external_oracle_for_local_only_recovery() -> None:
    native_key = make_native_key(input_identity="sha256:" + ("a" * 64))
    session = DecompilationSessionContext(
        function_ea=0x40A560,
        database_identity="test",
        top_level_epoch=1,
        native_key=native_key,
        input_identity_resolution=InputIdentityResolution(
            status=InputIdentityRecoveryStatus.RECOVERED_LOCAL_ONLY,
            input_identity=native_key.input_identity,
            provenance="recovered_from_d810_attestation",
            external_evidence_allowed=False,
            database_uuid="attested-db",
        ),
    )

    class _ReferenceOracleProvider:
        @staticmethod
        def reference_oracle_scope_for(*_args):
            return object()

        @staticmethod
        def reference_oracle_for(*_args):
            return object()

    state = _initialize_resolver_attachment(
        session,
        semantic_route_reference_oracle_provider=_ReferenceOracleProvider(),
    )

    assert state.semantic_route_reference_oracle_provider is not None
    assert (
        state.semantic_route_reference_oracle_provider.reference_oracle_scope_for(
            session.function_ea,
            native_key,
        )
        is None
    )
    assert (
        state.semantic_route_reference_oracle_provider.reference_oracle_for(
            session.function_ea,
            native_key,
            (0x40A570,),
        )
        is None
    )


def test_manager_loads_only_configured_relative_oracle_manifests(tmp_path) -> None:
    manifest = {
        "schema_version": 2,
        "publication_root_ea": "0x40AE3E",
        "run": {
            "run_id": "configured-a560-boundary",
            "function_ea": "0x40A560",
            "fixture_sha256": "a" * 64,
            "reference_binary_sha256": "b" * 64,
            "candidate_binary_sha256": "a" * 64,
            "reference_commit": "deadbeef",
            "runtime_image": "test-image",
            "runtime_image_id": "sha256:" + "c" * 64,
            "cache_disabled": True,
        },
        "routes": [
            {
                "route_id": "test:0x40A560:flow_route:0x40B52E",
                "function_ea": "0x40A560",
                "owner_ea": "0x40B51B",
                "rewrite_anchor_ea": "0x40B52E",
                "corridor": [["0x40B51B", "0x40B534"]],
                "reference_phase": "flow_route",
                "original_transfer_kind": "conditional",
                "final_transfer_kind": "direct",
                "direct_target_ea": "0x40AE3E",
                "true_target_ea": None,
                "false_target_ea": None,
                "predicate_kind": None,
                "reference_ledger_identity": "flow_route:0x40B52E",
                "reference_ledger": {"status": "committed"},
            }
        ],
    }
    (tmp_path / "a560.json").write_text(json.dumps(manifest), encoding="utf-8")

    registry = _load_semantic_route_reference_oracle_registry(
        {"semantic_route_oracle_manifests": ["a560.json"]},
        config_root=tmp_path,
    )

    assert registry is not None
    selection = registry.reference_oracle_for(
        0x40A560,
        make_native_key(
            input_identity="sha256:" + "a" * 64,
            function_rva=0xA560,
        ),
        (0x40B52E,),
    )
    assert selection is not None
    assert selection.run.run_id == "configured-a560-boundary"
    assert (
        _load_semantic_route_reference_oracle_registry({}, config_root=tmp_path) is None
    )
    with pytest.raises(ValueError, match="non-empty array"):
        _load_semantic_route_reference_oracle_registry(
            {"semantic_route_oracle_manifests": "a560.json"},
            config_root=tmp_path,
        )
    with pytest.raises(ValueError, match="inside the configuration root"):
        _load_semantic_route_reference_oracle_registry(
            {"semantic_route_oracle_manifests": ["../a560.json"]},
            config_root=tmp_path,
        )


def test_default_ollvm_profile_selects_complete_a560_flow_route_oracle() -> None:
    source_project = ProjectConfiguration.from_file(
        Path(__file__).parents[3]
        / "src"
        / "d810"
        / "conf"
        / "default_unflattening_ollvm.json"
    )
    runtime_selection = select_config_v2_default_project(source_project)
    assert runtime_selection is not None

    registry = _load_semantic_route_reference_oracle_registry(
        runtime_selection.runtime_project.additional_configuration
    )

    assert registry is not None
    selection = registry.reference_oracle_scope_for(
        0x40A560,
        make_native_key(
            input_identity=(
                "sha256:"
                "2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
            ),
            function_rva=0xA560,
        ),
    )
    assert selection is not None
    assert selection.run.reference_commit == (
        "21b0d4783703bc4fb6910cfae51d92cd683d2c65"
    )
    assert selection.run.runtime_image_id == (
        "sha256:360f91d9d4ace70d89e03893f1d895d94383fa0fe426ddba9d3898a7922b650a"
    )
    assert selection.publication_root_ea == 0x40A5B2
    assert len(selection.routes) == 93
    assert len({route.route_id for route in selection.routes}) == 93
    assert len({route.owner_ea for route in selection.routes}) == 93
    routes_by_anchor = {route.rewrite_anchor_ea: route for route in selection.routes}
    assert set(routes_by_anchor) >= {0x40A5C8, 0x40BB63, 0x40BED0, 0x40C4D2}
    entry_route = routes_by_anchor[0x40A5C8]
    assert entry_route.owner_ea == 0x40A5B2
    assert entry_route.direct_target_ea == 0x40BECC
    carrier_route = routes_by_anchor[0x40BB63]
    assert carrier_route.owner_ea == 0x40BB51
    assert carrier_route.direct_target_ea == 0x40ACF3
    first_conditional = routes_by_anchor[0x40BED0]
    assert first_conditional.predicate_kind == "z"
    assert first_conditional.true_target_ea == 0x40B9A6
    assert first_conditional.false_target_ea == 0x40C26D
    second_conditional = routes_by_anchor[0x40C4D2]
    assert second_conditional.predicate_kind == "z"
    assert second_conditional.true_target_ea == 0x40B199
    assert second_conditional.false_target_ea == 0x40ADA2


def test_current_mba_identity_index_uses_only_current_mba_publication_binding(
    monkeypatch,
) -> None:
    native_preanalysis = NativePreanalysisSessionState()
    binding = _current_mba_identity_binding()
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="test-session",
        function_ea=0x40A560,
    )
    state = resolver_session_state(session)
    state.semantic_route_reference_oracle_provider = SimpleNamespace(
        reference_oracle_scope_for=lambda *_args: object()
    )
    events: list[str] = []
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
        this=0x1234,
        build_graph=lambda: events.append("build_graph"),
    )
    assert state.bind_current_imported_publication(0x1234, binding)
    captured: dict[str, object] = {}
    index = SimpleNamespace(
        evidence_generation=native_preanalysis.evidence_generation,
        generation=0,
    )

    def build_index(current_mba, **kwargs):
        events.append("index")
        captured["mba"] = current_mba
        captured.update(kwargs)
        return index

    monkeypatch.setattr(
        MbaBlockIdentityIndex,
        "from_mba",
        staticmethod(build_index),
    )

    assert _build_current_mba_identity_index(session=session, mba=mba) is index
    assert captured["mba"] is mba
    assert captured["current_mba_identity_binding"] is binding
    assert "imported_instruction_origins" not in captured
    assert state.identity_index is index
    assert events == ["build_graph", "index"]


def test_current_mba_identity_index_is_graph_free_at_actual_generated(
    monkeypatch,
) -> None:
    native_preanalysis = NativePreanalysisSessionState()
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="generated-session",
        function_ea=0x40A560,
    )
    state = resolver_session_state(session)
    state.semantic_route_reference_oracle_provider = SimpleNamespace(
        reference_oracle_scope_for=lambda *_args: object()
    )
    index = SimpleNamespace(evidence_generation=0, generation=0)
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GENERATED,
        this=0x1234,
        build_graph=lambda: pytest.fail(
            "actual GENERATED identity indexing must not build a graph"
        ),
    )
    monkeypatch.setattr(
        MbaBlockIdentityIndex,
        "from_mba",
        staticmethod(lambda *_args, **_kwargs: index),
    )

    assert _build_current_mba_identity_index(session=session, mba=mba) is index
    assert state.identity_index is index


def test_current_mba_identity_index_rejects_previous_mba_binding(monkeypatch) -> None:
    native_preanalysis = NativePreanalysisSessionState()
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="test-session",
        function_ea=0x40A560,
    )
    state = resolver_session_state(session)
    state.semantic_route_reference_oracle_provider = SimpleNamespace(
        reference_oracle_scope_for=lambda *_args: object()
    )
    assert state.bind_current_imported_publication(
        0x1234,
        _current_mba_identity_binding(),
    )
    captured: dict[str, object] = {}
    index = SimpleNamespace(evidence_generation=0, generation=0)

    def build_index(_mba, **kwargs):
        captured.update(kwargs)
        return index

    monkeypatch.setattr(MbaBlockIdentityIndex, "from_mba", staticmethod(build_index))

    _build_current_mba_identity_index(
        session=session,
        mba=SimpleNamespace(
            maturity=ida_hexrays.MMAT_PREOPTIMIZED,
            this=0x5678,
            build_graph=lambda: None,
        ),
    )

    assert captured["current_mba_identity_binding"] is None
    assert "imported_instruction_origins" not in captured


def test_current_mba_identity_index_reports_ambiguous_candidate_owners(
    monkeypatch,
) -> None:
    import d810.core.observability as observability

    native_preanalysis = NativePreanalysisSessionState()
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="test-session",
        function_ea=0x40A560,
    )
    state = resolver_session_state(session)
    state.semantic_route_reference_oracle_provider = SimpleNamespace(
        reference_oracle_scope_for=lambda *_args: object()
    )

    class Insn:
        ea = 0x40D348
        next = None

    blocks = tuple(
        SimpleNamespace(
            serial=serial,
            start=0x40D348,
            head=Insn(),
        )
        for serial in (0, 1)
    )
    mba = SimpleNamespace(
        qty=len(blocks),
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
        this=0x1234,
        build_graph=lambda: None,
        get_mblock=lambda serial: blocks[int(serial)],
        map_fict_ea=lambda ea: int(ea),
    )
    events: list[object] = []
    monkeypatch.setattr(observability, "emit", events.append)

    index = _build_current_mba_identity_index(session=session, mba=mba)
    identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40D348,),
    )

    assert index.rebind_identity(identity).status.name == "AMBIGUOUS"
    (event,) = tuple(
        event for event in events if isinstance(event, IdentityDecisionObserved)
    )
    candidates = json.loads(event.candidates_json)
    assert tuple(candidate["block"] for candidate in candidates) == (
        "blk0@0x40D348",
        "blk1@0x40D348",
    )
    assert all(
        candidate["stable_identity"] == identity.to_dict() for candidate in candidates
    )


def test_current_mba_identity_index_abstains_before_locopt_without_route_authority(
    monkeypatch,
) -> None:
    native_preanalysis = NativePreanalysisSessionState()
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="protected-session",
        function_ea=0x18000C090,
    )
    state = resolver_session_state(session)
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
        this=0x1234,
        build_graph=lambda: pytest.fail(
            "protected PREOPT must not build the live graph"
        ),
    )
    monkeypatch.setattr(
        MbaBlockIdentityIndex,
        "from_mba",
        staticmethod(
            lambda *_args, **_kwargs: pytest.fail(
                "protected PREOPT must not capture a live identity index"
            )
        ),
    )

    assert _build_current_mba_identity_index(session=session, mba=mba) is None
    assert state.identity_index is None


def test_current_mba_identity_index_accepts_typed_frontend_evidence_before_locopt(
    monkeypatch,
) -> None:
    native_preanalysis = NativePreanalysisSessionState()
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="frontend-normalization-session",
        function_ea=0x18000C090,
    )
    state = resolver_session_state(session)
    events: list[str] = []
    index = SimpleNamespace(evidence_generation=0, generation=0)
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
        this=0x1234,
        build_graph=lambda: events.append("build_graph"),
    )
    monkeypatch.setattr(
        NativePreanalysisSessionState,
        "frontend_normalization_evidence_for",
        lambda self, key: object() if self is native_preanalysis and key == NATIVE_KEY else None,
    )
    monkeypatch.setattr(
        MbaBlockIdentityIndex,
        "from_mba",
        staticmethod(lambda *_args, **_kwargs: index),
    )

    assert _build_current_mba_identity_index(session=session, mba=mba) is index
    assert state.identity_index is index
    assert events == ["build_graph"]


def test_current_mba_identity_index_never_rebuilds_graph_after_locopt(
    monkeypatch,
) -> None:
    native_preanalysis = NativePreanalysisSessionState()
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="post-locopt-session",
        function_ea=0x18000C090,
    )
    state = resolver_session_state(session)
    index = SimpleNamespace(evidence_generation=0, generation=0)
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT2,
        this=0x1234,
        build_graph=lambda: pytest.fail(
            "Hex-Rays permits mba.build_graph() only once before LOCOPT"
        ),
    )
    monkeypatch.setattr(
        MbaBlockIdentityIndex,
        "from_mba",
        staticmethod(lambda *_args, **_kwargs: index),
    )

    assert _build_current_mba_identity_index(session=session, mba=mba) is index
    assert state.identity_index is index


def test_current_mba_mutation_gateway_uses_session_lifecycle_authority() -> None:
    native_preanalysis = NativePreanalysisSessionState(evidence_generation=2)
    session = SimpleNamespace(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        identity_key="test-session",
        function_ea=0x40A560,
    )
    index = MbaBlockIdentityIndex.from_bindings(
        session_id=session.identity_key,
        generation=7,
        evidence_generation=2,
        native_key=NATIVE_KEY,
        bindings=(),
    )
    event_emitter = object()

    gateway = _new_current_mba_mutation_gateway(
        session=session,
        identity_index=index,
        maturity=3,
        event_emitter=event_emitter,
    )

    assert isinstance(
        gateway.lifecycle_authority,
        FragmentPublicationLifecycleAuthority,
    )
    assert gateway.lifecycle_authority is not native_preanalysis
    assert gateway.lifecycle_authority.evidence_generation == 2
    assert gateway.identity_index is index
    assert gateway.event_emitter is event_emitter


@pytest.mark.parametrize(
    ("maturity", "records_normalization_fact"),
    (
        (ida_hexrays.MMAT_PREOPTIMIZED, True),
        (ida_hexrays.MMAT_GLBOPT1, False),
    ),
)
def test_manager_constructs_the_semantic_native_body_materializer(
    maturity,
    records_normalization_fact,
) -> None:
    from d810.hexrays.mutation.detached_handler_island import (
        PreoptUnionSemanticNativeBodyMaterializer,
    )

    mba = SimpleNamespace(maturity=maturity)
    session = DecompilationSessionContext(
        function_ea=0x40A560,
        database_identity="test",
        top_level_epoch=1,
        native_key=NATIVE_KEY,
    )
    materializer = _new_semantic_native_body_materializer(
        session=session,
        mba=mba,
    )

    assert isinstance(
        materializer,
        PreoptUnionSemanticNativeBodyMaterializer,
    )
    assert materializer.mba is mba
    assert materializer.function_ea == 0x40A560
    assert bool(callable(materializer.prepared_fact_observer)) is (
        records_normalization_fact
    )


def test_manager_constructs_the_calls_native_body_materializer() -> None:
    from d810.hexrays.mutation.detached_handler_island import (
        CallsSemanticNativeBodyMaterializer,
    )

    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_CALLS)
    materializer = _new_semantic_native_body_materializer(
        session=SimpleNamespace(function_ea=0x40A560),
        mba=mba,
    )

    assert isinstance(
        materializer,
        CallsSemanticNativeBodyMaterializer,
    )
    assert materializer.mba is mba
    assert materializer.function_ea == 0x40A560


def test_calls_native_body_companion_request_queues_range_and_restart(
    monkeypatch,
) -> None:
    import d810.core.observability as observability

    session = DecompilationSessionContext(
        function_ea=0x40A560,
        database_identity="test",
        top_level_epoch=1,
        native_key=NATIVE_KEY,
    )
    events: list[object] = []
    monkeypatch.setattr(observability, "emit", events.append)
    materializer = _new_semantic_native_body_materializer(
        session=session,
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_CALLS),
    )
    native_range = (0x40B9A6, 0x40BB75)

    assert materializer.request_call_companions is not None
    assert materializer.request_call_companions((native_range,))

    state = resolver_session_state(session)
    assert state.pending_call_companion_ranges == (native_range,)
    assert session.native_preanalysis.has_pending_generated_restart
    assert len(events) == 1
    event = events[0]
    assert event.event_kind == "semantic_native_body_companion_request"
    assert event.payload == {
        "ranges": [
            {
                "start_ea": native_range[0],
                "end_ea": native_range[1],
            }
        ],
        "queue_changed": True,
        "restart_requested": True,
        "accepted": True,
    }


@pytest.mark.parametrize(
    "maturity",
    [
        ida_hexrays.MMAT_LOCOPT,
        ida_hexrays.MMAT_GLBOPT2,
        ida_hexrays.MMAT_GLBOPT3,
    ],
)
def test_manager_returns_none_for_maturity_without_a_materializer(maturity) -> None:
    """A recognized maturity with no materializer is routine, not an error.

    MMAT_GLBOPT2 is reached on EVERY decompile.  Raising made the sole consumer
    (DecompilationLifecycleCoordinator.new_semantic_native_body_materializer)
    swallow the ValueError and log a full traceback at DEBUG every run, which
    reads as a failure in any debug-logged dump while nothing has failed.
    """
    assert (
        _new_semantic_native_body_materializer(
            session=SimpleNamespace(function_ea=0x40A560),
            mba=SimpleNamespace(maturity=maturity),
        )
        is None
    )


def test_manager_rejects_unrecognized_native_body_materializer_maturity() -> None:
    """A maturity id Hex-Rays does not define IS a programming error."""
    with pytest.raises(
        ValueError,
        match="unrecognized semantic native-body materializer maturity",
    ):
        _new_semantic_native_body_materializer(
            session=SimpleNamespace(function_ea=0x40A560),
            mba=SimpleNamespace(maturity=0xBADF00D),
        )


def test_manager_preserves_applied_work_on_aborted_mutation_receipt(
    monkeypatch,
) -> None:
    observed: list[MutationReceiptObserved] = []
    monkeypatch.setattr("d810.core.observability.emit", observed.append)

    D810Manager._on_mutation_aborted(
        MbaMutationAborted(
            session_id="terminal-fragment-session",
            function_ea=0x40A560,
            maturity=1,
            mba_generation=7,
            evidence_generation=3,
            mutation_batch_id="terminal-fragment-batch",
            kind=StructuralMutationKind.FRAGMENT_PUBLICATION,
            planned_operation_count=8,
            applied_operation_count=8,
            description="publish terminal semantic fragment",
            reason=(
                "postpublication semantic validation failed: "
                "observable_return_carrier:return-value"
            ),
            discarded_versions=(
                LogicalBlockVersion(
                    version_id=LogicalBlockVersionId("logical-terminal", 1),
                    handle=MbaBlockHandle.observed_ephemeral(
                        session_id="terminal-fragment-session",
                        token="physical-terminal-v1",
                    ),
                    generation=8,
                    predecessor_version_id=LogicalBlockVersionId(
                        "logical-terminal",
                        0,
                    ),
                ),
            ),
            fragment_plan_id="terminal-fragment",
            fragment_atomic_group_id="terminal-group",
            root_publication_groups=(
                MbaMutationRootPublicationGroup(
                    group_id="root-group:entry",
                    predecessor_block_id="entry",
                    predecessor_anchor_ea=0x40A560,
                    edge_ids=("replacement:entry:direct",),
                    edge_roles=(SemanticEdgeRole.DIRECT,),
                    original_block_ids=("original",),
                    replacement_block_ids=("replacement",),
                    publication_attempted=True,
                    publication_succeeded=True,
                    rollback_attempted=True,
                    rollback_succeeded=True,
                ),
            ),
            fragment_staged=True,
            root_publication_attempted=True,
            root_publication_succeeded=True,
            rollback_attempted=True,
            rollback_succeeded=True,
            fragment_failures=(
                MbaSemanticFragmentFailure(
                    failure_kind="stage",
                    phase="stage",
                    error_type="SemanticFragmentBackendRejected",
                    error_message=(
                        "fragment plan requires an imported native-body materializer"
                    ),
                ),
                MbaSemanticFragmentFailure(
                    failure_kind="verifier",
                    phase="stage_cleanup",
                    error_type="RuntimeError",
                    error_message="INTERR: 50856",
                    interr_code=50856,
                    verification_context=("staged semantic fragment rollback sweep"),
                ),
            ),
        )
    )

    assert len(observed) == 1
    assert observed[0].mutation_batch_id == "terminal-fragment-batch"
    assert observed[0].planned_operation_count == 8
    assert observed[0].applied_operation_count == 8
    assert observed[0].outcome == "aborted"
    assert "observable_return_carrier:return-value" in observed[0].reason
    assert observed[0].fragment_plan_id == "terminal-fragment"
    assert observed[0].fragment_atomic_group_id == "terminal-group"
    assert observed[0].fragment_staged
    assert observed[0].root_publication_succeeded
    assert observed[0].rollback_succeeded
    assert observed[0].fragment_failures == (
        SemanticFragmentFailureObserved(
            failure_kind="stage",
            phase="stage",
            error_type="SemanticFragmentBackendRejected",
            error_message=(
                "fragment plan requires an imported native-body materializer"
            ),
        ),
        SemanticFragmentFailureObserved(
            failure_kind="verifier",
            phase="stage_cleanup",
            error_type="RuntimeError",
            error_message="INTERR: 50856",
            interr_code=50856,
            verification_context="staged semantic fragment rollback sweep",
        ),
    )
    assert observed[0].root_publication_groups[0].rollback_succeeded
    assert len(observed[0].version_transitions) == 1
    transition = observed[0].version_transitions[0]
    assert transition.proxy_token == "logical-terminal"
    assert transition.version == 1
    assert transition.physical_handle_token == "physical-terminal-v1"
    assert transition.generation == 8
    assert transition.provenance == "observed_ephemeral"
    assert transition.stable_identity_json is None
    assert transition.anchor_ea is None
    assert transition.predecessor_version == 0
    assert (transition.from_state, transition.to_state) == ("staged", "aborted")


def test_manager_translates_detached_route_oracle_before_receipt(monkeypatch) -> None:
    observed: list[SemanticFragmentRouteOracleComparedObserved] = []
    monkeypatch.setattr("d810.core.observability.emit", observed.append)
    comparison = RouteOracleComparison(
        route_id="rhad:0x40A560:flow_route:0x40B52E",
        maturity="DETACHED_PREPUBLICATION",
        candidate_variant="detached_prepublication",
        outcome="diverged",
        first_divergence=True,
        failed_invariant="transfer_kind",
        owner_ea=0x40B51B,
        rewrite_anchor_ea=0x40B52E,
        oracle_shape=None,
        candidate_shape=None,
        reason="staged route remained conditional",
    )
    result = DetachedRouteOracleResult(
        plan_id="a560-boundary",
        atomic_group_id="route@0x40B52E",
        comparisons=(comparison,),
    )

    D810Manager._on_semantic_fragment_route_oracle_compared(
        MbaSemanticFragmentRouteOracleCompared(
            session_id="a560-session",
            function_ea=0x40A560,
            maturity=1,
            mba_generation=7,
            evidence_generation=3,
            mutation_batch_id="a560-route-batch",
            run_id="a560-v33-boundary",
            plan_id=result.plan_id,
            atomic_group_id=result.atomic_group_id,
            reference_ledger_identities=((comparison.route_id, "flow_route:0x40B52E"),),
            result=result,
        )
    )

    assert len(observed) == 1
    assert observed[0].mutation_batch_id == "a560-route-batch"
    assert observed[0].run_id == "a560-v33-boundary"
    assert observed[0].comparisons == (comparison,)
    assert observed[0].reference_ledger_identities == (
        (comparison.route_id, "flow_route:0x40B52E"),
    )


def test_preflight_starts_one_session_and_hands_its_state_to_the_resolver(
    monkeypatch,
) -> None:
    session = SimpleNamespace(
        native_preanalysis=NativePreanalysisSessionState(),
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        event=SimpleNamespace(function_ea=0x401000),
    )
    events: list[tuple[object, object]] = []
    calls: list[object] = []

    class _Lifecycle:
        def ensure_hexrays_session(self, **kwargs):
            calls.append(("ensure", kwargs))
            return session, True

        def begin_native_preanalysis(self, current_session):
            calls.append(("preanalysis.begin", current_session))

        def finish_native_preanalysis(self, current_session):
            calls.append(("preanalysis.finish", current_session))

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    manager._database_identity = "sample.i64"
    manager.event_emitter = SimpleNamespace(
        emit=lambda event, payload: events.append((event, payload))
    )
    resolution = SimpleNamespace(jmp_targets=(0x401100,))
    monkeypatch.setattr(
        computed_goto_resolver,
        "_has_unresolved_computed_goto",
        lambda function_ea: function_ea == 0x401000,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "stage_computed_goto_preanalysis",
        lambda function_ea, *, state: calls.append(("stage", state)) or resolution,
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_detached_handler_snippets",
        lambda state: calls.append(("prepare", state)) or 3,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_terminal_return_carrier_evidence",
        lambda state: calls.append(("prepare-carriers", state)) or 2,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "discover_static_native_bootstrap_routes",
        lambda function_ea, state: (
            calls.append(("discover-bootstrap", function_ea, state)) or True
        ),
    )

    assert manager.prepare_native_preanalysis(0x401000) == 5

    state = resolver_session_state(session)
    # Session events belong to the coordinator. The manager must not mirror
    # the event when its preflight reuses that permanent lifecycle port.
    assert events == []
    assert calls == [
        (
            "ensure",
            {"function_ea": 0x401000, "database_identity": "sample.i64"},
        ),
        ("stage", state),
        ("preanalysis.begin", session),
        ("prepare-carriers", state),
        ("prepare", state),
        ("discover-bootstrap", 0x401000, state),
        ("preanalysis.finish", session),
    ]
    assert state.materialization is not None
    assert state.materialization.resolution is resolution


def test_preflight_records_complete_call_companion_mismatch(
    monkeypatch,
) -> None:
    import d810.core.observability as observability

    session = DecompilationSessionContext(
        function_ea=0x401000,
        database_identity="sample.i64",
        top_level_epoch=1,
        native_key=NATIVE_KEY,
    )

    class _Lifecycle:
        @staticmethod
        def ensure_hexrays_session(**_kwargs):
            return session, True

        @staticmethod
        def begin_native_preanalysis(_session):
            return None

        @staticmethod
        def finish_native_preanalysis(_session):
            return None

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    manager._database_identity = "sample.i64"
    resolution = SimpleNamespace(jmp_targets=(0x401100,))
    monkeypatch.setattr(
        computed_goto_resolver,
        "_has_unresolved_computed_goto",
        lambda _function_ea: True,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "stage_computed_goto_preanalysis",
        lambda _function_ea, *, state: resolution,
    )
    mismatch = computed_goto_resolver.CallCompanionPreparationOutcome(
        native_range=(0x40C26D, 0x40C2FB),
        calls_native_ranges=((0x40C26D, 0x40C2F9),),
        component_target_ea=0x40C26D,
        captured=False,
        preopt_call_eas=(0x40C2A9, 0x40C2BE),
        calls_call_eas=(0x40C2A9, 0x40C2F0),
        mismatch_ea=0x40C2BE,
        reason="call_ea_set_mismatch",
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_requested_detached_call_companions",
        lambda _state: (mismatch,),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_terminal_return_carrier_evidence",
        lambda _state: 0,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prepare_detached_handler_snippets",
        lambda _state: 0,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "discover_static_native_bootstrap_routes",
        lambda _function_ea, _state: False,
    )
    events: list[object] = []
    monkeypatch.setattr(observability, "emit", events.append)

    assert manager.prepare_native_preanalysis(0x401000) == 0

    assert len(events) == 1
    event = events[0]
    assert event.event_kind == "semantic_native_body_companion_prepared"
    assert event.payload["calls_native_ranges"] == [
        {"start_ea": 0x40C26D, "end_ea": 0x40C2F9}
    ]
    assert event.payload["preopt_call_eas"] == [0x40C2A9, 0x40C2BE]
    assert event.payload["calls_call_eas"] == [0x40C2A9, 0x40C2F0]
    assert event.payload["mismatch_ea"] == 0x40C2BE


def test_decompile_controller_runs_one_followup_for_pending_generated_restart(
    monkeypatch,
) -> None:
    calls: list[tuple[str, int]] = []
    pending = iter((True, False))

    class _Lifecycle:
        @staticmethod
        def current_session(_function_ea: int):
            return None

        @staticmethod
        def has_exhausted_poison_restart(_function_ea: int) -> bool:
            return False

        @staticmethod
        def has_pending_generated_restart(function_ea: int) -> bool:
            calls.append(("pending", function_ea))
            return next(pending)

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    monkeypatch.setattr(
        manager,
        "prepare_native_preanalysis",
        lambda function_ea: calls.append(("prepare", function_ea)) or 0,
    )

    rounds = iter(("first", "final"))
    result = manager.decompile_with_native_preanalysis(
        0x401000,
        lambda: calls.append(("decompile", 0x401000)) or next(rounds),
        lambda: calls.append(("invalidate", 0x401000)),
    )

    assert result == "final"
    assert calls == [
        ("prepare", 0x401000),
        ("invalidate", 0x401000),
        ("decompile", 0x401000),
        ("pending", 0x401000),
        ("prepare", 0x401000),
        ("invalidate", 0x401000),
        ("decompile", 0x401000),
        ("pending", 0x401000),
    ]


def test_decompile_controller_releases_stack_capacity_witness_when_decompile_raises(
    monkeypatch,
) -> None:
    calls: list[tuple[str, object]] = []
    session = object()

    class _Lifecycle:
        @staticmethod
        def current_session(function_ea: int):
            calls.append(("session", function_ea))
            return session

    class _Lease:
        @staticmethod
        def release() -> None:
            calls.append(("release", session))

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    monkeypatch.setattr(
        manager,
        "prepare_native_preanalysis",
        lambda function_ea: calls.append(("prepare", function_ea)) or 0,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "acquire_detached_call_stack_capacity_witness",
        lambda current_session: calls.append(("acquire", current_session)) or _Lease(),
        raising=False,
    )

    def decompile():
        calls.append(("decompile", 0x401000))
        raise ValueError("decompile failed")

    with pytest.raises(ValueError, match="decompile failed"):
        manager.decompile_with_native_preanalysis(
            0x401000,
            decompile,
            lambda: calls.append(("invalidate", 0x401000)),
        )

    assert calls == [
        ("prepare", 0x401000),
        ("session", 0x401000),
        ("acquire", session),
        ("invalidate", 0x401000),
        ("decompile", 0x401000),
        ("release", session),
    ]


def test_decompile_controller_services_poison_restart_from_second_round(
    monkeypatch,
) -> None:
    calls: list[tuple[str, int]] = []
    pending = iter((True, True, False))

    class _Lifecycle:
        @staticmethod
        def current_session(_function_ea: int):
            return None

        @staticmethod
        def has_exhausted_poison_restart(_function_ea: int) -> bool:
            return False

        @staticmethod
        def has_pending_generated_restart(function_ea: int) -> bool:
            calls.append(("pending", function_ea))
            return next(pending)

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    monkeypatch.setattr(
        manager,
        "prepare_native_preanalysis",
        lambda function_ea: calls.append(("prepare", function_ea)) or 0,
    )
    rounds = iter(("first", "poisoned-second", "fresh-third"))

    result = manager.decompile_with_native_preanalysis(
        0x401000,
        lambda: calls.append(("decompile", 0x401000)) or next(rounds),
        lambda: calls.append(("invalidate", 0x401000)),
    )

    assert result == "fresh-third"
    assert [kind for kind, _ea in calls].count("decompile") == 3
    assert [kind for kind, _ea in calls].count("pending") == 3


def test_decompile_controller_binds_post_recovery_dispatcher_evidence(
    monkeypatch,
) -> None:
    pending = iter((True, True, True, False))

    class _Lifecycle:
        @staticmethod
        def current_session(_function_ea: int):
            return None

        @staticmethod
        def has_exhausted_poison_restart(_function_ea: int) -> bool:
            return False

        @staticmethod
        def has_pending_generated_restart(_function_ea: int) -> bool:
            return next(pending)

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    monkeypatch.setattr(manager, "prepare_native_preanalysis", lambda _ea: 0)
    rounds: list[int] = []

    result = manager.decompile_with_native_preanalysis(
        0x401000,
        lambda: rounds.append(len(rounds) + 1) or rounds[-1],
        lambda: None,
    )

    assert result == 4
    assert rounds == [1, 2, 3, 4]


def test_decompile_controller_binds_rebound_dispatcher_route_closure(
    monkeypatch,
) -> None:
    pending = iter((True, True, True, True, False))

    class _Lifecycle:
        @staticmethod
        def current_session(_function_ea: int):
            return None

        @staticmethod
        def has_exhausted_poison_restart(_function_ea: int) -> bool:
            return False

        @staticmethod
        def has_pending_generated_restart(_function_ea: int) -> bool:
            return next(pending)

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    monkeypatch.setattr(manager, "prepare_native_preanalysis", lambda _ea: 0)
    rounds: list[int] = []

    result = manager.decompile_with_native_preanalysis(
        0x401000,
        lambda: rounds.append(len(rounds) + 1) or rounds[-1],
        lambda: None,
    )

    assert result == 5
    assert rounds == [1, 2, 3, 4, 5]


def test_decompile_controller_fails_loudly_if_restart_remains_after_poison_retry(
    monkeypatch,
) -> None:
    class _Lifecycle:
        @staticmethod
        def current_session(_function_ea: int):
            return None

        @staticmethod
        def has_exhausted_poison_restart(_function_ea: int) -> bool:
            return False

        @staticmethod
        def has_pending_generated_restart(_function_ea: int) -> bool:
            return True

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    monkeypatch.setattr(manager, "prepare_native_preanalysis", lambda _ea: 0)
    rounds: list[str] = []

    with pytest.raises(RuntimeError, match="restart budget exhausted"):
        manager.decompile_with_native_preanalysis(
            0x401000,
            lambda: rounds.append("decompile"),
            lambda: None,
        )

    assert rounds == [
        "decompile",
        "decompile",
        "decompile",
        "decompile",
        "decompile",
    ]


def test_decompile_controller_fails_on_distinct_post_recovery_poison(
    monkeypatch,
) -> None:
    state = NativePreanalysisSessionState(evidence_generation=5)
    assert state.request_generated_restart(
        evidence_family="ordinary",
        reason="ordinary evidence retry",
    )
    assert state.consume_generated_restart()

    class _Lifecycle:
        @staticmethod
        def current_session(_function_ea: int):
            return None

        @staticmethod
        def has_pending_generated_restart(_function_ea: int) -> bool:
            return state.has_pending_generated_restart

        @staticmethod
        def has_exhausted_poison_restart(_function_ea: int) -> bool:
            return state.has_exhausted_poison_restart

    manager = D810Manager.__new__(D810Manager)
    manager.decompilation_lifecycle = _Lifecycle()
    monkeypatch.setattr(manager, "prepare_native_preanalysis", lambda _ea: 0)
    rounds = 0

    def decompile():
        nonlocal rounds
        rounds += 1
        if rounds == 1:
            assert state.request_poisoned_generation_restart(reason="first poison")
        else:
            assert state.consume_generated_restart()
            assert not state.request_poisoned_generation_restart(
                reason="fresh third-round poison"
            )
        return f"round-{rounds}"

    with pytest.raises(RuntimeError, match="poison restart exhausted"):
        manager.decompile_with_native_preanalysis(0x401000, decompile, lambda: None)

    assert rounds == 2
