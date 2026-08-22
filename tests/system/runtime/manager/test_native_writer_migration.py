"""Runtime-bound provenance tests for the manager-owned native writer."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptStatus,
    ExecutionDomain,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.hexrays.preanalysis.indirect_jump_labels import (
    IndirectLabelMaterializationPlan,
    NativePatchPlanRequest,
)
from d810.manager import native_writer_migration
from d810.manager.native_normalization import (
    NativeNormalizationOutcome,
    NativeNormalizationResult,
)
from d810.manager.native_writer_migration import (
    ManagerOwnedDeadEdgeNormalizer,
    ManagerOwnedNativePatchRequestExecutor,
    PreparedNativePatchRequest,
)


@contextmanager
def _parent_attempt_scope(parent_attempt_id, events=None):
    if events is not None:
        events.append("entered")
    try:
        yield parent_attempt_id
    finally:
        if events is not None:
            events.append("closed")


def test_dead_edge_normalizer_checks_user_policy_before_discovery(tmp_path) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    calls: list[str] = []
    normalizer = ManagerOwnedDeadEdgeNormalizer(
        gateway=object(),
        user_enabled=lambda _function_ea: False,
        execution_journal=journal,
        parent_attempt_scope_for_function=lambda _function_ea: (_ for _ in ()).throw(
            AssertionError("disabled normalization requested a parent")
        ),
        discover_candidates=lambda _function_ea: (_ for _ in ()).throw(
            AssertionError("disabled normalization ran semantic discovery")
        ),
        build_plan=lambda *_args: (_ for _ in ()).throw(
            AssertionError("disabled normalization built a plan")
        ),
        apply_plan=lambda _plan: calls.append("apply"),
    )

    outcome = normalizer(0x401000)

    assert outcome.outcome is NativeNormalizationOutcome.NOT_AUTHORIZED
    assert outcome.reason == "USER_NOT_OPTED_IN"
    assert calls == []
    journal.close()


def _native_request(function_ea: int = 0x1000) -> NativePatchPlanRequest:
    return NativePatchPlanRequest(
        materialization=IndirectLabelMaterializationPlan(
            function_ea=function_ea,
            label_start=0x1010,
            label_end=0x1020,
            table_address=0x2000,
            table_count=1,
            target_eas=(0x1010,),
        ),
        dispatch_jump_ea=0x1008,
        switch_start_ea=None,
        install_switch_info=False,
        state_base=1,
        state_var_stkoff=None,
    )


def _native_executor(
    journal,
    parent,
    built_requests,
    *,
    user_enabled=lambda _request: True,
    build_plan=None,
):
    plan = SimpleNamespace(
        plan_id="plan-1",
        plan_hash="hash-1",
        proof_hash="semantic-hash-1",
        metadata_target_fingerprint="metadata-hash-1",
    )
    result = SimpleNamespace(success=True)
    build_plan = build_plan or (
        lambda proposal, _attempt: (
            built_requests.append(proposal)
            or PreparedNativePatchRequest(plan=plan, observe_result=lambda: result)
        )
    )
    return ManagerOwnedNativePatchRequestExecutor(
        gateway=SimpleNamespace(
            record_diagnostic_snapshot=lambda _plan: "snapshot-1",
            record_certificate_validation_receipt=lambda _plan, _certificate: (
                "preflight-2"
            ),
        ),
        user_enabled=user_enabled,
        execution_journal=journal,
        parent_attempt_for_request=lambda _request: parent.attempt_id,
        build_plan=build_plan,
    ), plan, result


def _native_outcomes():
    return iter(
        (
            NativeNormalizationResult(
                outcome=NativeNormalizationOutcome.APPLIED,
                apply_receipt=SimpleNamespace(
                    transaction_id=SimpleNamespace(value="tx-1"),
                    preflight_receipt_id="preflight-1",
                    ok=True,
                ),
                certificate=SimpleNamespace(
                    certificate_id="certificate-1",
                    schema_version=4,
                    native_plan_hash="hash-1",
                    semantic_plan_hash="semantic-hash-1",
                    metadata_target_fingerprint="metadata-hash-1",
                ),
                reason=None,
            ),
            NativeNormalizationResult(
                outcome=NativeNormalizationOutcome.ALREADY_NORMALIZED,
                apply_receipt=None,
                certificate=SimpleNamespace(
                    certificate_id="certificate-1",
                    schema_version=4,
                    native_plan_hash="hash-1",
                    semantic_plan_hash="semantic-hash-1",
                    metadata_target_fingerprint="metadata-hash-1",
                ),
                reason="native_plan_hash matches an existing applied certificate",
            ),
        )
    )


def test_native_materialization_arms_one_shot_reuse_under_same_parent(
    tmp_path, monkeypatch
) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    request = _native_request()
    built_requests = []
    executor, plan, result = _native_executor(
        journal, parent, built_requests
    )
    # The exact prepared plan is applied twice, but the builder runs once.
    outcomes = _native_outcomes()
    monkeypatch.setattr(
        native_writer_migration,
        "authorize_and_apply",
        lambda _request, *, gateway: next(outcomes),
    )
    executor.arm_certificate_reuse_verification(0x1000)
    assert executor(request) is result
    receipt = executor.inspect_last_receipt(function_ea=0x1000)
    assert receipt.plan_id == plan.plan_id
    assert receipt.plan_hash == plan.plan_hash
    assert len(receipt.attempts) == 2
    first, second = receipt.attempts
    assert first.attempt.status is ExecutionAttemptStatus.COMPLETED
    assert first.normalization.outcome is NativeNormalizationOutcome.APPLIED
    assert second.attempt.status is ExecutionAttemptStatus.ABSTAINED
    assert second.normalization.outcome is NativeNormalizationOutcome.ALREADY_NORMALIZED
    assert second.attempt.parent_attempt_id == first.attempt.parent_attempt_id
    assert second.normalization.certificate.certificate_id == (
        first.normalization.certificate.certificate_id
    )
    assert second.normalization.apply_receipt is None
    assert len(built_requests) == 1
    assert sum(
        "native_patch_transaction" in {effect.kind for effect in item.attempt.effect_refs}
        for item in receipt.attempts
    ) == 1
    journal.close()


def test_native_materialization_policy_opt_out_consumes_arm_without_leakage(
    tmp_path, monkeypatch
) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session, stage_id="hexrays_preanalysis", domain=ExecutionDomain.HOOK
    )
    enabled = iter((False, True))
    outcomes = _native_outcomes()
    monkeypatch.setattr(
        native_writer_migration,
        "authorize_and_apply",
        lambda _request, *, gateway: next(outcomes),
    )
    built_requests = []
    executor, _plan, _result = _native_executor(
        journal,
        parent,
        built_requests,
        user_enabled=lambda _request: next(enabled),
    )
    executor.arm_certificate_reuse_verification(0x1000)
    assert executor(_native_request()).reason == "native_patch_policy_disabled"
    assert executor(_native_request()).success
    assert len(executor.inspect_last_receipt().attempts) == 1
    journal.close()


def test_native_materialization_different_function_does_not_reuse_or_leak(
    tmp_path, monkeypatch
) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session, stage_id="hexrays_preanalysis", domain=ExecutionDomain.HOOK
    )
    outcomes = iter(
        (
            NativeNormalizationResult(
                outcome=NativeNormalizationOutcome.APPLIED,
                apply_receipt=None,
                certificate=None,
                reason=None,
            ),
            NativeNormalizationResult(
                outcome=NativeNormalizationOutcome.APPLIED,
                apply_receipt=None,
                certificate=None,
                reason=None,
            ),
        )
    )
    monkeypatch.setattr(
        native_writer_migration,
        "authorize_and_apply",
        lambda _request, *, gateway: next(outcomes),
    )
    built_requests = []
    executor, _plan, _result = _native_executor(
        journal, parent, built_requests
    )
    executor.arm_certificate_reuse_verification(0x1000)
    executor(_native_request(0x2000))
    assert len(executor.inspect_last_receipt().attempts) == 1
    executor(_native_request(0x1000))
    assert len(executor.inspect_last_receipt().attempts) == 1
    journal.close()


def test_native_materialization_exception_clears_one_shot_arm(tmp_path, monkeypatch) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session, stage_id="hexrays_preanalysis", domain=ExecutionDomain.HOOK
    )
    build_calls = [True]
    built_requests = []

    def build_plan(proposal, _attempt):
        if build_calls:
            build_calls.pop()
            raise RuntimeError("boom")
        return PreparedNativePatchRequest(
            plan=SimpleNamespace(
                plan_id="plan-1",
                plan_hash="hash-1",
                proof_hash="semantic-hash-1",
                metadata_target_fingerprint="metadata-hash-1",
            ),
            observe_result=lambda: SimpleNamespace(success=True),
        )

    executor, _plan, _result = _native_executor(
        journal,
        parent,
        built_requests,
        build_plan=build_plan,
    )
    executor.arm_certificate_reuse_verification(0x1000)
    with pytest.raises(RuntimeError, match="boom"):
        executor(_native_request())
    monkeypatch.setattr(
        native_writer_migration,
        "authorize_and_apply",
        lambda _request, *, gateway: NativeNormalizationResult(
            outcome=NativeNormalizationOutcome.APPLIED,
            apply_receipt=None,
            certificate=None,
            reason=None,
        ),
    )
    executor(_native_request())
    assert len(executor.inspect_last_receipt().attempts) == 1
    journal.close()


def test_native_materialization_clear_drops_receipt_for_stop_and_reload(
    tmp_path, monkeypatch
) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session, stage_id="hexrays_preanalysis", domain=ExecutionDomain.HOOK
    )
    monkeypatch.setattr(
        native_writer_migration,
        "authorize_and_apply",
        lambda _request, *, gateway: NativeNormalizationResult(
            outcome=NativeNormalizationOutcome.APPLIED,
            apply_receipt=None,
            certificate=None,
            reason=None,
        ),
    )
    executor, _plan, _result = _native_executor(
        journal, parent, []
    )
    executor(_native_request())
    executor.arm_certificate_reuse_verification(0x1000)
    executor.clear_lifecycle_state()
    with pytest.raises(RuntimeError, match="no native materialization receipt"):
        executor.inspect_last_receipt()
    journal.close()


def test_dead_edge_normalizer_issues_plan_from_real_child_attempt(tmp_path) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    candidate = SimpleNamespace(proof_kind="z3_opaque_predicate")
    plan = SimpleNamespace(plan_id="dead-edge-plan")
    built_with = []

    def build_plan(function_ea, candidates, authorizing_attempt_id):
        built_with.append((function_ea, candidates, authorizing_attempt_id))
        return plan

    applied = NativeNormalizationResult(
        outcome=NativeNormalizationOutcome.APPLIED,
        apply_receipt=SimpleNamespace(
            transaction_id=SimpleNamespace(value="native-tx-7"),
            preflight_receipt_id="preflight-7",
        ),
        certificate=SimpleNamespace(certificate_id="certificate-7"),
        reason=None,
    )
    normalizer = ManagerOwnedDeadEdgeNormalizer(
        gateway=SimpleNamespace(record_diagnostic_snapshot=lambda _plan: "snapshot-7"),
        user_enabled=lambda _function_ea: True,
        execution_journal=journal,
        parent_attempt_scope_for_function=lambda _function_ea: _parent_attempt_scope(
            parent.attempt_id
        ),
        discover_candidates=lambda _function_ea: ((candidate,), ()),
        build_plan=build_plan,
        apply_plan=lambda candidate_plan: applied if candidate_plan is plan else None,
    )

    outcome = normalizer(0x401000)

    child = journal.only_attempt(
        session_id,
        stage_id="native_dead_edge_normalizer",
    )
    assert outcome is applied
    assert child.status is ExecutionAttemptStatus.COMPLETED
    assert child.domain is ExecutionDomain.NATIVE_NORMALIZATION
    assert child.parent_attempt_id == parent.attempt_id
    assert built_with == [(0x401000, (candidate,), child.attempt_id)]
    assert [(effect.kind, effect.ref_id) for effect in child.effect_refs] == [
        ("native_patch_proposal", "dead-edge-plan"),
        ("native_patch_preflight", "preflight-7"),
        ("native_patch_diagnostic_snapshot", "snapshot-7"),
        ("native_patch_transaction", "native-tx-7"),
        ("native_patch_certificate", "certificate-7"),
    ]
    journal.close()


@pytest.mark.parametrize(
    "outcome",
    (
        NativeNormalizationOutcome.ALREADY_NORMALIZED,
        NativeNormalizationOutcome.REJECTED,
    ),
)
def test_dead_edge_normalizer_closes_parent_scope_for_non_applied_outcomes(
    tmp_path,
    outcome,
) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    events: list[str] = []
    result = NativeNormalizationResult(
        outcome=outcome,
        apply_receipt=None,
        certificate=None,
        reason=outcome.value,
    )
    normalizer = ManagerOwnedDeadEdgeNormalizer(
        gateway=SimpleNamespace(
            record_diagnostic_snapshot=lambda _plan: "snapshot-closed",
            record_certificate_validation_receipt=(
                lambda _plan, _certificate: "validation-closed"
            ),
        ),
        user_enabled=lambda _function_ea: True,
        execution_journal=journal,
        parent_attempt_scope_for_function=lambda _function_ea: _parent_attempt_scope(
            parent.attempt_id, events
        ),
        discover_candidates=lambda _function_ea: (
            (SimpleNamespace(proof_kind="single_trip_loop_peel"),),
            (),
        ),
        build_plan=lambda *_args: SimpleNamespace(plan_id="closed-plan"),
        apply_plan=lambda _plan: result,
    )

    assert normalizer(0x401000) is result
    assert events == ["entered", "closed"]
    journal.close()


def test_dead_edge_normalizer_selects_one_deterministic_proof_batch(tmp_path) -> None:
    journal = ExecutionJournalStore(tmp_path / "execution.sqlite")
    session_id = DecompilationSessionId.new()
    parent = journal.begin_attempt(
        session_id,
        stage_id="hexrays_preanalysis",
        domain=ExecutionDomain.HOOK,
    )
    single_trip = SimpleNamespace(proof_kind="single_trip_loop_peel", site_ea=0x10)
    opaque = (
        SimpleNamespace(proof_kind="z3_opaque_predicate", site_ea=0x20),
        SimpleNamespace(proof_kind="z3_opaque_predicate", site_ea=0x30),
    )
    built_with = []
    result = NativeNormalizationResult(
        outcome=NativeNormalizationOutcome.APPLIED,
        apply_receipt=SimpleNamespace(
            transaction_id=SimpleNamespace(value="mixed-proof-tx"),
            preflight_receipt_id="mixed-proof-preflight",
        ),
        certificate=None,
        reason=None,
    )

    def _build(function_ea, candidates, attempt_id):
        built_with.append((function_ea, candidates, attempt_id))
        assert {candidate.proof_kind for candidate in candidates} == {
            "z3_opaque_predicate"
        }
        return SimpleNamespace(plan_id="selected-proof-plan")

    normalizer = ManagerOwnedDeadEdgeNormalizer(
        gateway=SimpleNamespace(
            record_diagnostic_snapshot=lambda _plan: "mixed-proof-snapshot"
        ),
        user_enabled=lambda _function_ea: True,
        execution_journal=journal,
        parent_attempt_scope_for_function=lambda _function_ea: _parent_attempt_scope(
            parent.attempt_id
        ),
        discover_candidates=lambda _function_ea: ((single_trip, *opaque), ()),
        build_plan=_build,
        apply_plan=lambda _plan: result,
    )

    assert normalizer(0x401000) is result
    assert len(built_with) == 1
    child = journal.only_attempt(
        session_id,
        stage_id="native_dead_edge_normalizer",
    )
    assert child.details == {
        "function_ea": 0x401000,
        "candidate_count": 3,
        "selected_candidate_count": 2,
        "selected_proof_kind": "z3_opaque_predicate",
        "deferred_candidate_count": 1,
        "deferred_proof_kinds": ("single_trip_loop_peel",),
    }
    journal.close()
