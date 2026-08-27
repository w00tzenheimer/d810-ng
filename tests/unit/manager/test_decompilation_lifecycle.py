"""Unit tests for manager-owned decompilation lifecycle coordination."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
    GeneratedRestartConsumer,
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
from d810.core.function_execution_identity import FunctionExecutionIdentity
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptStatus,
    ExecutionDomain,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.core.provider_phase import ProviderPhaseSnapshot
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.maturity import IRMaturity
from d810.backends.hexrays.native_preanalysis_key import (
    NativePreanalysisIdentityResolution,
)
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


def test_current_function_execution_identity_uses_verified_resolution() -> None:
    calls: list[tuple[str, object]] = []
    verified_key = NativePreanalysisKey(
        input_identity="sha256:" + "a" * 64,
        processor="metapc",
        bitness=64,
        function_rva=NATIVE_KEY.function_rva,
        function_fingerprint=NATIVE_KEY.function_fingerprint,
        profile_fingerprint=NATIVE_KEY.profile_fingerprint,
        sdk_fingerprint=NATIVE_KEY.sdk_fingerprint,
    )
    resolution = InputIdentityResolution(
        status=InputIdentityRecoveryStatus.LOADER_SHA_CAPTURED,
        input_identity=verified_key.input_identity,
        provenance="verified_loader_sha256",
        external_evidence_allowed=True,
        database_uuid="12345678-1234-5678-1234-567812345678",
    )
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=_PreanalysisRuntime(calls),
        analysis_runtime=_AnalysisRuntime(calls),
        execution_scope_service=_ExecutionScopeService(calls),
        native_preanalysis_key_provider=lambda _function_ea: (
            NativePreanalysisIdentityResolution(verified_key, resolution)
        ),
    )
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    coordinator.merge_facts(verified_key, _native_facts(key=verified_key))

    identity = coordinator.current_function_execution_identity(
        0x401000, IRMaturity.CANONICAL
    )

    assert isinstance(identity, FunctionExecutionIdentity)
    assert identity.input_identity == verified_key.input_identity
    assert identity.external_evidence_allowed is True
    assert identity.decompilation_session_id == session.session_id.value
    assert identity.top_level_epoch == session.top_level_epoch
    assert identity.evidence_generation == 1


def test_current_function_execution_identity_fails_without_active_session() -> None:
    coordinator, _runtime = _coordinator([])

    with pytest.raises(ValueError, match="active session"):
        coordinator.current_function_execution_identity(0x401000, IRMaturity.CANONICAL)


def test_current_function_execution_identity_falls_back_to_idb_local() -> None:
    calls: list[tuple[str, object]] = []
    database_uuid = "12345678-1234-5678-1234-567812345678"
    local_key = NativePreanalysisKey(
        input_identity=f"idb-local:{database_uuid}",
        processor=NATIVE_KEY.processor,
        bitness=NATIVE_KEY.bitness,
        function_rva=NATIVE_KEY.function_rva,
        function_fingerprint=NATIVE_KEY.function_fingerprint,
        profile_fingerprint=NATIVE_KEY.profile_fingerprint,
        sdk_fingerprint=NATIVE_KEY.sdk_fingerprint,
    )
    resolution = InputIdentityResolution(
        status=InputIdentityRecoveryStatus.IDB_LOCAL,
        input_identity=local_key.input_identity,
        provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid=database_uuid,
    )
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=_PreanalysisRuntime(calls),
        analysis_runtime=_AnalysisRuntime(calls),
        execution_scope_service=_ExecutionScopeService(calls),
        native_preanalysis_key_provider=lambda _function_ea: (
            NativePreanalysisIdentityResolution(local_key, resolution)
        ),
    )
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    identity = coordinator.current_function_execution_identity(
        0x401000, IRMaturity.CANONICAL
    )

    assert identity.input_identity == f"idb-local:{database_uuid}"
    assert identity.external_evidence_allowed is False
    assert identity.input_identity_provenance == "current_idb"


def test_key_only_legacy_local_identity_reuses_native_uuid_and_session() -> None:
    calls: list[tuple[str, object]] = []
    database_uuid = "12345678-1234-5678-1234-567812345678"
    local_key = NativePreanalysisKey(
        input_identity=f"idb-local:{database_uuid}",
        processor=NATIVE_KEY.processor,
        bitness=NATIVE_KEY.bitness,
        function_rva=NATIVE_KEY.function_rva,
        function_fingerprint=NATIVE_KEY.function_fingerprint,
        profile_fingerprint=NATIVE_KEY.profile_fingerprint,
        sdk_fingerprint=NATIVE_KEY.sdk_fingerprint,
    )
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=_PreanalysisRuntime(calls),
        analysis_runtime=_AnalysisRuntime(calls),
        execution_scope_service=_ExecutionScopeService(calls),
        native_preanalysis_key_provider=lambda _function_ea: local_key,
    )
    session, _created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    identity = coordinator.current_function_execution_identity(
        0x401000, IRMaturity.CANONICAL
    )

    assert identity.input_identity == local_key.input_identity
    assert identity.database_uuid == database_uuid
    assert identity.decompilation_session_id == session.session_id.value
    assert identity.external_evidence_allowed is False


def test_key_only_legacy_sha_identity_fails_without_uuid_authority() -> None:
    coordinator, _runtime = _coordinator([])
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    with pytest.raises(ValueError, match="database UUID authority"):
        coordinator.current_function_execution_identity(0x401000, IRMaturity.CANONICAL)


def test_unverified_sha_resolution_is_forced_to_local_identity() -> None:
    calls: list[tuple[str, object]] = []
    database_uuid = "12345678-1234-5678-1234-567812345678"
    unverified_key = make_native_key(input_identity="sha256:" + "a" * 64)
    resolution = InputIdentityResolution(
        status=InputIdentityRecoveryStatus.RECOVERED_LOCAL_ONLY,
        input_identity=unverified_key.input_identity,
        provenance="recovered_from_d810_attestation",
        external_evidence_allowed=False,
        database_uuid=database_uuid,
    )
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=_PreanalysisRuntime(calls),
        analysis_runtime=_AnalysisRuntime(calls),
        execution_scope_service=_ExecutionScopeService(calls),
        native_preanalysis_key_provider=lambda _function_ea: (
            NativePreanalysisIdentityResolution(unverified_key, resolution)
        ),
    )
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    identity = coordinator.current_function_execution_identity(
        0x401000, IRMaturity.CANONICAL
    )

    assert identity.input_identity == f"idb-local:{database_uuid}"
    assert identity.external_evidence_allowed is False


def test_mismatched_local_uuid_authority_fails_closed() -> None:
    calls: list[tuple[str, object]] = []
    key_uuid = "12345678-1234-5678-1234-567812345678"
    resolution_uuid = "87654321-4321-8765-4321-876543218765"
    local_key = NativePreanalysisKey(
        input_identity=f"idb-local:{key_uuid}",
        processor=NATIVE_KEY.processor,
        bitness=NATIVE_KEY.bitness,
        function_rva=NATIVE_KEY.function_rva,
        function_fingerprint=NATIVE_KEY.function_fingerprint,
        profile_fingerprint=NATIVE_KEY.profile_fingerprint,
        sdk_fingerprint=NATIVE_KEY.sdk_fingerprint,
    )
    resolution = InputIdentityResolution(
        status=InputIdentityRecoveryStatus.IDB_LOCAL,
        input_identity=local_key.input_identity,
        provenance="current_idb",
        external_evidence_allowed=False,
        database_uuid=resolution_uuid,
    )
    coordinator = DecompilationLifecycleCoordinator(
        preanalysis_runtime=_PreanalysisRuntime(calls),
        analysis_runtime=_AnalysisRuntime(calls),
        execution_scope_service=_ExecutionScopeService(calls),
        native_preanalysis_key_provider=lambda _function_ea: (
            NativePreanalysisIdentityResolution(local_key, resolution)
        ),
    )
    coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    with pytest.raises(ValueError, match="UUID authorities disagree"):
        coordinator.current_function_execution_identity(0x401000, IRMaturity.CANONICAL)


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


def test_session_event_reuses_a_stable_session_id_across_the_lifecycle() -> None:
    """``session.event`` must correlate every call to the same journal session.

    ``DecompilationSessionEvent.session_id`` defaults via a factory purely so
    ``DecompilationSessionContext.event`` stays source-compatible without
    passing it explicitly (see ``core/decompilation_session.py``). That
    default factory must not be allowed to mint a *fresh* session id on
    every ``.event`` access, or every consumer of that property (SESSION_
    STARTED vs SESSION_FINISHED, ``preanalysis_runtime.begin_session`` vs
    ``analysis_runtime.begin_session``, ...) would observe an uncorrelated
    session identity for what is actually one top-level decompile.
    """
    coordinator, _runtime = _coordinator([])

    session, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    assert isinstance(session.session_id, DecompilationSessionId)
    first_event = session.event
    second_event = session.event
    assert first_event.session_id == second_event.session_id == session.session_id


def test_new_top_level_session_gets_a_fresh_session_id() -> None:
    """A new top-level decompile mints a new session -- it must not reuse an old id."""
    coordinator, _runtime = _coordinator([])

    first, _ = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )
    first_session_id = first.session_id
    coordinator.finish_hexrays_session()

    second, created = coordinator.ensure_hexrays_session(
        function_ea=0x401000,
        database_identity="sample.i64",
    )

    assert created is True
    assert second.session_id != first_session_id


def test_new_top_level_session_is_durably_bound_to_its_function(tmp_path) -> None:
    coordinator, _runtime = _coordinator([])
    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        coordinator.execution_journal = journal

        session, created = coordinator.ensure_hexrays_session(
            function_ea=0x401000,
            database_identity="sample.i64",
        )

        assert created is True
        assert journal.latest_session_for_function(0x401000) == session.session_id


def test_session_finish_flushes_callback_summary_before_parent_completion(
    tmp_path, monkeypatch
) -> None:
    coordinator, _runtime = _coordinator([])
    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        coordinator.execution_journal = journal
        session, _created = coordinator.ensure_hexrays_session(
            function_ea=0x401000,
            database_identity="sample.i64",
        )
        assert session.preanalysis_attempt_id is not None
        journal.summarize_callback_abstention(
            session.session_id,
            parent_attempt_id=session.preanalysis_attempt_id,
            callback_kind="optinsn",
            stage_id="instruction_optimizer",
            maturity="GLBOPT1",
            reason_code="no_instruction_change",
        )
        observed_parent_statuses: list[ExecutionAttemptStatus] = []
        original_flush = journal.flush_callback_summaries

        def observe_flush(*args, **kwargs):
            parent = journal.get_attempt(session.preanalysis_attempt_id)
            assert parent is not None
            observed_parent_statuses.append(parent.status)
            return original_flush(*args, **kwargs)

        monkeypatch.setattr(journal, "flush_callback_summaries", observe_flush)

        coordinator.finish_hexrays_session()

        assert observed_parent_statuses == [ExecutionAttemptStatus.STARTED]
        assert (
            journal.only_attempt(
                session.session_id, stage_id="callback_summary"
            ).details["total_abstentions"]
            == 1
        )
        assert journal.get_attempt(session.preanalysis_attempt_id).status is (
            ExecutionAttemptStatus.COMPLETED
        )


@pytest.mark.parametrize("operation", ("bind_session", "begin_attempt"))
def test_journal_setup_failure_does_not_block_a_live_decompilation(
    tmp_path,
    monkeypatch,
    operation: str,
) -> None:
    """Provenance storage is best-effort and never a session authority."""
    coordinator, _runtime = _coordinator([])
    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        coordinator.execution_journal = journal

        def fail(*_args, **_kwargs):
            raise OSError("journal unavailable")

        monkeypatch.setattr(journal, operation, fail)
        session, created = coordinator.ensure_hexrays_session(
            function_ea=0x401000,
            database_identity="sample.i64",
        )

    assert created is True
    assert session.preanalysis_attempt_id is None
    assert session.execution_journal is None


def test_fresh_hint_application_is_a_child_journal_record_not_a_cache_read(
    tmp_path,
) -> None:
    calls: list[tuple[str, object]] = []
    coordinator, runtime = _coordinator(calls)
    runtime.hints = SimpleNamespace(
        func_ea=0x401000,
        obfuscation_type="state_machine",
        confidence=0.75,
        recommended_inferences=("unflattening",),
        suppress_stages=("legacy-stage",),
    )

    with ExecutionJournalStore(tmp_path / "execution.sqlite") as journal:
        coordinator.execution_journal = journal
        session, _created = coordinator.ensure_hexrays_session(
            function_ea=0x401000,
            database_identity="sample.i64",
        )

        coordinator.analyze_current_function(
            function_ea=0x401000,
            source="instruction",
        )

        attempt = journal.only_attempt(
            session.session_id,
            stage_id="execution_hints:fresh_analysis",
        )
        assert attempt.domain is ExecutionDomain.HOOK
        assert attempt.parent_attempt_id == session.preanalysis_attempt_id
        assert attempt.status is ExecutionAttemptStatus.COMPLETED
        assert attempt.details["hint_source"] == "fresh_analysis"
        assert attempt.details["trigger_source"] == "instruction"
        assert len(attempt.effect_refs) == 1
        assert attempt.effect_refs[0].kind == "fresh_execution_hints"
        assert attempt.effect_refs[0].detail["recommended_inferences"] == (
            "unflattening",
        )
        assert "cached" not in str(attempt.details)


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

    assert (
        session.native_preanalysis.consume_generated_restart(
            consumer=GeneratedRestartConsumer.FLOWCHART,
        )
        is not None
    )
    assert coordinator.finish_hexrays_session() is None
    assert coordinator.current_session(0x401000) is None


def test_analysis_without_hints_does_not_apply_or_record_execution_scope_outcome() -> (
    None
):
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
        gate.reference_oracle_for(0x401000, NATIVE_KEY, (0x401020,)) == "anchor-result"
    )
    assert calls == ["scope", "anchors"]


def test_missing_identity_logs_debug_and_abstains_before_session_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostics: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        decompilation_lifecycle,
        "logger",
        SimpleNamespace(debug=lambda *args: diagnostics.append(args)),
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

    assert diagnostics[0][0].startswith("D810 native mutation abstained")
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
