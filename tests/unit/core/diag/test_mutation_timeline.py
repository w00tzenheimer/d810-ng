from __future__ import annotations

from unittest.mock import patch

import pytest

from d810.core.diag import create_diag_database
from d810.core.diag.event_handlers import install_diag_event_handlers, uninstall_diag_event_handlers
from d810.core.observability import emit, reset_diagnostic_bus
from d810.core.observability_events import (
    DiagnosticSessionObserved,
    FragmentValidationOutcomeObserved,
    LogicalBlockVersionTransitionObserved,
    MutationPlanItemObserved,
    MutationPlanObserved,
    MutationReceiptObserved,
)


@pytest.fixture
def diag_conn():
    return create_diag_database(":memory:").connection()


@pytest.fixture(autouse=True)
def sink(diag_conn):
    reset_diagnostic_bus()
    with patch(
        "d810.core.diag.event_handlers.get_diag_conn",
        new=lambda *_args, **_kwargs: diag_conn,
    ):
        install_diag_event_handlers()
        emit(DiagnosticSessionObserved("s1", 0x40C8B0, 1, "{}", "active"))
        yield
        uninstall_diag_event_handlers()
    reset_diagnostic_bus()


def test_plan_and_receipt_are_correlated_by_gateway_batch(diag_conn) -> None:
    item = MutationPlanItemObserved(
        item_index=0,
        mutation_kind="edge_redirect",
        source_serial=17,
        source_anchor_ea=0x40CA3D,
        source_identity_json='{"native_ranges":[]}',
        target_serial=21,
        target_anchor_ea=0x40CD76,
        target_identity_json='{"native_ranges":[]}',
        disposition="planned",
        reason="resolver route",
    )
    emit(
        MutationPlanObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="batch-1",
            mutation_kind="edge_redirect",
            planned_operation_count=1,
            mba_generation=8,
            evidence_generation=3,
            maturity="MMAT_CALLS",
            description="apply route",
            items=(item,),
        )
    )
    emit(
        MutationReceiptObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="batch-1",
            mutation_kind="edge_redirect",
            pre_generation=8,
            post_generation=9,
            planned_operation_count=1,
            applied_operation_count=1,
            evidence_generation=3,
            maturity="MMAT_CALLS",
            outcome="committed",
            description="apply route",
            reason="",
            affected_identity_json=(item.source_identity_json,),
            affected_anchor_eas=(item.source_anchor_ea,),
        )
    )

    assert diag_conn.execute(
        "SELECT mutation_batch_id,item_index,source_anchor_ea_i64 "
        "FROM mutation_plan_items"
    ).fetchone() == ("batch-1", 0, 0x40CA3D)
    assert diag_conn.execute(
        "SELECT mutation_batch_id,pre_generation,post_generation,outcome "
        "FROM mutation_receipts"
    ).fetchone() == ("batch-1", 8, 9, "committed")
    assert diag_conn.execute(
        "SELECT event_seq,event_kind,correlation_id FROM lifecycle_events "
        "ORDER BY event_seq"
    ).fetchall() == [
        (1, "session_active", None),
        (2, "mutation_plan", "batch-1"),
        (3, "mutation_receipt", "batch-1"),
    ]


def test_terminal_effect_plan_and_aborted_receipt_preserve_applied_work(
    diag_conn,
) -> None:
    items = (
        MutationPlanItemObserved(
            item_index=0,
            mutation_kind="semantic_fragment_return_carrier_materialization",
            source_serial=None,
            source_anchor_ea=0x40C890,
            source_identity_json='{"native_ranges":[]}',
            target_serial=None,
            target_anchor_ea=0x40C898,
            target_identity_json='{"native_ranges":[]}',
            disposition="planned",
            reason="return-carrier:return-value",
        ),
        MutationPlanItemObserved(
            item_index=1,
            mutation_kind="semantic_fragment_terminal_return_materialization",
            source_serial=None,
            source_anchor_ea=0x40C8A0,
            source_identity_json='{"native_ranges":[]}',
            target_serial=None,
            target_anchor_ea=None,
            target_identity_json=None,
            disposition="planned",
            reason="terminal-return:function-return",
        ),
    )
    emit(
        MutationPlanObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="terminal-batch",
            mutation_kind="fragment_publication",
            planned_operation_count=2,
            mba_generation=8,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            description="publish terminal fragment",
            items=items,
            fragment_plan_id="terminal-fragment",
            fragment_atomic_group_id="terminal-atomic-group",
            fragment_plan_json=(
                '{"atomic_group_id":"terminal-atomic-group",'
                '"plan_id":"terminal-fragment"}'
            ),
        )
    )
    emit(
        MutationReceiptObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="terminal-batch",
            mutation_kind="fragment_publication",
            pre_generation=8,
            post_generation=8,
            planned_operation_count=2,
            applied_operation_count=2,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            outcome="aborted",
            description="publish terminal fragment",
            reason=(
                "postpublication semantic validation failed: "
                "observable_return_carrier:return-value"
            ),
            fragment_plan_id="terminal-fragment",
            fragment_atomic_group_id="terminal-atomic-group",
            fragment_staged=True,
            root_publication_attempted=True,
            root_publication_succeeded=True,
            rollback_attempted=True,
            rollback_succeeded=True,
        )
    )

    assert diag_conn.execute(
        "SELECT item_index,mutation_kind,source_anchor_ea_i64,"
        "target_anchor_ea_i64 FROM mutation_plan_items "
        "WHERE mutation_batch_id='terminal-batch' ORDER BY item_index"
    ).fetchall() == [
        (
            0,
            "semantic_fragment_return_carrier_materialization",
            0x40C890,
            0x40C898,
        ),
        (
            1,
            "semantic_fragment_terminal_return_materialization",
            0x40C8A0,
            None,
        ),
    ]
    assert diag_conn.execute(
        "SELECT planned_operation_count,applied_operation_count,outcome,reason "
        "FROM mutation_receipts WHERE mutation_batch_id='terminal-batch'"
    ).fetchone() == (
        2,
        2,
        "aborted",
        "postpublication semantic validation failed: "
        "observable_return_carrier:return-value",
    )


def test_fragment_receipt_persists_complete_semantic_transaction(
    diag_conn,
) -> None:
    plan_json = (
        '{"atomic_group_id":"atomic-route-1","blocks":[{"block_id":"replacement"}],'
        '"operations":[{"operation_id":"route-1"}],"plan_id":"fragment-1"}'
    )
    emit(
        MutationPlanObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="fragment-batch",
            mutation_kind="fragment_publication",
            planned_operation_count=1,
            mba_generation=8,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            description="publish semantic fragment",
            fragment_plan_id="fragment-1",
            fragment_atomic_group_id="atomic-route-1",
            fragment_plan_json=plan_json,
        )
    )
    prevalidation = (
        FragmentValidationOutcomeObserved(
            phase="prepublication",
            postcondition="root_reachability",
            subject_id="fragment-1",
            passed=True,
            reason="all replacements reachable",
            block_ids=("replacement",),
        ),
        FragmentValidationOutcomeObserved(
            phase="prepublication",
            postcondition="original_supersession",
            subject_id="original",
            passed=True,
            reason="owned original unreachable",
            block_ids=("original",),
        ),
        FragmentValidationOutcomeObserved(
            phase="prepublication",
            postcondition="dispatcher_absence",
            subject_id="dispatcher",
            passed=True,
            reason="dispatcher residue unreachable",
            block_ids=("dispatcher",),
        ),
        FragmentValidationOutcomeObserved(
            phase="prepublication",
            postcondition="use_def_integrity",
            subject_id="condition-value",
            passed=True,
            reason="definition reaches condition use",
            block_ids=("replacement",),
        ),
        FragmentValidationOutcomeObserved(
            phase="prepublication",
            postcondition="def_use_integrity",
            subject_id="condition-value",
            passed=True,
            reason="condition definition has expected uses",
            block_ids=("replacement",),
        ),
        FragmentValidationOutcomeObserved(
            phase="prepublication",
            postcondition="flag_corridor_integrity",
            subject_id="branch-flags",
            passed=True,
            reason="no intervening flag clobber",
            block_ids=("replacement",),
        ),
        FragmentValidationOutcomeObserved(
            phase="prepublication",
            postcondition="value_range_proven",
            subject_id="selector-domain",
            passed=True,
            reason="portable range preserved",
            block_ids=("replacement",),
        ),
    )
    postvalidation = (
        FragmentValidationOutcomeObserved(
            phase="postpublication",
            postcondition="root_authority",
            subject_id="fragment-1",
            passed=True,
            reason="published root owns entry route",
            block_ids=("replacement",),
        ),
        FragmentValidationOutcomeObserved(
            phase="postpublication",
            postcondition="postvalidation_coverage",
            subject_id="fragment-1",
            passed=True,
            reason="all required observable semantics checked",
            block_ids=("replacement",),
        ),
    )
    emit(
        MutationReceiptObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="fragment-batch",
            mutation_kind="fragment_publication",
            pre_generation=8,
            post_generation=9,
            planned_operation_count=1,
            applied_operation_count=1,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            outcome="committed",
            description="publish semantic fragment",
            reason="",
            fragment_plan_id="fragment-1",
            fragment_atomic_group_id="atomic-route-1",
            fragment_staged=True,
            root_publication_attempted=True,
            root_publication_succeeded=True,
            rollback_attempted=False,
            rollback_succeeded=None,
            validation_outcomes=prevalidation + postvalidation,
            version_transitions=(
                LogicalBlockVersionTransitionObserved(
                    proxy_token="logical-original",
                    from_version=0,
                    from_state="published",
                    to_version=0,
                    to_state="retired",
                ),
                LogicalBlockVersionTransitionObserved(
                    proxy_token="logical-original",
                    from_version=1,
                    from_state="staged",
                    to_version=1,
                    to_state="published",
                ),
            ),
        )
    )

    assert diag_conn.execute(
        "SELECT plan_id,atomic_group_id,plan_json,outcome,"
        "fragment_staged,root_publication_attempted,"
        "root_publication_succeeded,rollback_attempted,rollback_succeeded "
        "FROM semantic_fragment_transactions"
    ).fetchone() == (
        "fragment-1",
        "atomic-route-1",
        plan_json,
        "committed",
        1,
        1,
        1,
        0,
        None,
    )
    assert diag_conn.execute(
        "SELECT phase,postcondition,subject_id,passed,block_ids_json "
        "FROM semantic_fragment_validation_outcomes "
        "WHERE mutation_batch_id='fragment-batch' ORDER BY outcome_index"
    ).fetchall() == [
        (
            outcome.phase,
            outcome.postcondition,
            outcome.subject_id,
            int(outcome.passed),
            (
                '["' + '","'.join(outcome.block_ids) + '"]'
                if outcome.block_ids
                else "[]"
            ),
        )
        for outcome in prevalidation + postvalidation
    ]
    assert diag_conn.execute(
        "SELECT proxy_token,from_version,from_state,to_version,to_state "
        "FROM logical_block_version_transitions "
        "WHERE mutation_batch_id='fragment-batch' ORDER BY transition_index"
    ).fetchall() == [
        ("logical-original", 0, "published", 0, "retired"),
        ("logical-original", 1, "staged", 1, "published"),
    ]
    assert diag_conn.execute(
        "SELECT event_kind,outcome FROM semantic_fragment_transaction_events "
        "WHERE mutation_batch_id='fragment-batch' ORDER BY event_index"
    ).fetchall() == [
        ("plan_recorded", "planned"),
        ("fragment_staged", "completed"),
        ("prepublication_validation", "passed"),
        ("root_publication", "published"),
        ("postpublication_validation", "passed"),
        ("receipt", "committed"),
    ]


def test_aborted_fragment_persists_failed_postcondition_and_rollback(
    diag_conn,
) -> None:
    emit(
        MutationPlanObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="aborted-fragment",
            mutation_kind="fragment_publication",
            planned_operation_count=1,
            mba_generation=8,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            description="publish semantic fragment",
            fragment_plan_id="fragment-2",
            fragment_atomic_group_id="atomic-route-2",
            fragment_plan_json=(
                '{"atomic_group_id":"atomic-route-2","blocks":[],'
                '"operations":[],"plan_id":"fragment-2"}'
            ),
        )
    )
    emit(
        MutationReceiptObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="aborted-fragment",
            mutation_kind="fragment_publication",
            pre_generation=8,
            post_generation=8,
            planned_operation_count=1,
            applied_operation_count=1,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            outcome="aborted",
            description="publish semantic fragment",
            reason="postpublication root authority failed",
            fragment_plan_id="fragment-2",
            fragment_atomic_group_id="atomic-route-2",
            fragment_staged=True,
            root_publication_attempted=True,
            root_publication_succeeded=True,
            rollback_attempted=True,
            rollback_succeeded=True,
            validation_outcomes=(
                FragmentValidationOutcomeObserved(
                    phase="prepublication",
                    postcondition="root_reachability",
                    subject_id="fragment-2",
                    passed=True,
                    reason="replacement reachable",
                    block_ids=("replacement",),
                ),
                FragmentValidationOutcomeObserved(
                    phase="postpublication",
                    postcondition="root_authority",
                    subject_id="fragment-2",
                    passed=False,
                    reason="original root remained authoritative",
                    block_ids=("original", "replacement"),
                ),
            ),
            version_transitions=(
                LogicalBlockVersionTransitionObserved(
                    proxy_token="logical-original",
                    from_version=1,
                    from_state="staged",
                    to_version=1,
                    to_state="aborted",
                ),
            ),
        )
    )

    assert diag_conn.execute(
        "SELECT outcome,root_publication_succeeded,rollback_attempted,"
        "rollback_succeeded FROM semantic_fragment_transactions "
        "WHERE mutation_batch_id='aborted-fragment'"
    ).fetchone() == ("aborted", 1, 1, 1)
    assert diag_conn.execute(
        "SELECT phase,postcondition,passed,reason "
        "FROM semantic_fragment_validation_outcomes "
        "WHERE mutation_batch_id='aborted-fragment' ORDER BY outcome_index"
    ).fetchall() == [
        (
            "prepublication",
            "root_reachability",
            1,
            "replacement reachable",
        ),
        (
            "postpublication",
            "root_authority",
            0,
            "original root remained authoritative",
        ),
    ]
    assert diag_conn.execute(
        "SELECT event_kind,outcome FROM semantic_fragment_transaction_events "
        "WHERE mutation_batch_id='aborted-fragment' ORDER BY event_index"
    ).fetchall() == [
        ("plan_recorded", "planned"),
        ("fragment_staged", "completed"),
        ("prepublication_validation", "passed"),
        ("root_publication", "published"),
        ("postpublication_validation", "failed"),
        ("rollback", "succeeded"),
        ("receipt", "aborted"),
    ]


def test_fragment_receipt_scope_mismatch_leaves_no_partial_receipt(
    diag_conn,
) -> None:
    emit(
        MutationPlanObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="scope-mismatch",
            mutation_kind="fragment_publication",
            planned_operation_count=1,
            mba_generation=8,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            description="publish semantic fragment",
            fragment_plan_id="expected-plan",
            fragment_atomic_group_id="expected-group",
            fragment_plan_json=(
                '{"atomic_group_id":"expected-group",'
                '"plan_id":"expected-plan"}'
            ),
        )
    )

    emit(
        MutationReceiptObserved(
            session_id="s1",
            func_ea=0x40C8B0,
            mutation_batch_id="scope-mismatch",
            mutation_kind="fragment_publication",
            pre_generation=8,
            post_generation=8,
            planned_operation_count=1,
            applied_operation_count=0,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            outcome="aborted",
            description="publish semantic fragment",
            reason="scope drift",
            fragment_plan_id="wrong-plan",
            fragment_atomic_group_id="wrong-group",
        )
    )

    assert diag_conn.execute(
        "SELECT COUNT(*) FROM mutation_receipts "
        "WHERE mutation_batch_id='scope-mismatch'"
    ).fetchone() == (0,)
    assert diag_conn.execute(
        "SELECT event_kind FROM lifecycle_events "
        "WHERE correlation_id='scope-mismatch' ORDER BY event_seq"
    ).fetchall() == [("mutation_plan",)]
