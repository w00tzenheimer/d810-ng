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
from d810.manager.native_normalization import (
    NativeNormalizationOutcome,
    NativeNormalizationResult,
)
from d810.manager.native_writer_migration import ManagerOwnedDeadEdgeNormalizer


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
