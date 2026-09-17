"""Contracts for portable CFG transaction references and records."""

from __future__ import annotations

import inspect

import pytest

from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import (
    BoundCfgTransaction,
    CfgProjection,
    CfgTransactionFailure,
    CfgTransactionPhase,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
    PlanInsnRef,
    PreparedCfgTransaction,
    TransactionAttemptId,
)


def test_plan_local_refs_are_nominal_and_replay_stable() -> None:
    """A duplicate diagnostic digest must not collapse distinct local IDs."""
    creation_intents = (
        (PlanBlockRef("plan-1", "block-a"), "body-digest:identical"),
        (PlanBlockRef("plan-1", "block-b"), "body-digest:identical"),
    )
    first, _first_diagnostic_digest = creation_intents[0]
    second, _second_diagnostic_digest = creation_intents[1]

    assert {digest for _ref, digest in creation_intents} == {"body-digest:identical"}
    assert len({ref for ref, _digest in creation_intents}) == 2
    assert first != second
    assert first == PlanBlockRef("plan-1", "block-a")
    assert TransactionAttemptId("plan-1", "attempt-a") != TransactionAttemptId(
        "plan-1", "attempt-b"
    )


def test_plan_instruction_ref_requires_a_plan_block_ref() -> None:
    """Instruction-local identity is anchored by its nominal plan block."""
    block = PlanBlockRef("plan-1", "block-a")

    assert PlanInsnRef(block, "instruction-a").block == block
    with pytest.raises(TypeError, match="PlanBlockRef"):
        PlanInsnRef("block-a", "instruction-a")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("factory", "args"),
    [
        (PlanBlockRef, ("", "block-a")),
        (PlanBlockRef, ("plan-1", "   ")),
        (PlanInsnRef, (PlanBlockRef("plan-1", "block-a"), "")),
        (LogicalBlockRef, ("", "proxy-a", 0)),
        (LogicalBlockRef, ("session-1", "", 0)),
        (LogicalBlockRef, ("session-1", "proxy-a", -1)),
        (TransactionAttemptId, ("", "attempt-a")),
        (TransactionAttemptId, ("plan-1", "")),
    ],
)
def test_nominal_reference_ids_reject_blank_or_negative_values(
    factory: object, args: tuple[object, ...]
) -> None:
    """Portable handles cannot be blank or use negative snapshot-local numbers."""
    with pytest.raises((TypeError, ValueError)):
        factory(*args)  # type: ignore[operator]


def test_reference_constructors_expose_no_live_or_diagnostic_identity_inputs() -> None:
    """Portable reference identity cannot be constructed from live identity shortcuts."""
    forbidden = {"ea", "badaddr", "body_hash", "serial"}
    for ref_type in (PlanBlockRef, PlanInsnRef, NativeBlockRef, LogicalBlockRef):
        assert not (forbidden & set(inspect.signature(ref_type).parameters))


def test_transactions_keep_plan_and_binding_authority_consistent() -> None:
    """Transaction records reject cross-plan attempts and duplicate bindings."""
    attempt = TransactionAttemptId("plan-1", "attempt-a")
    block = PlanBlockRef("plan-1", "block-a")
    projection = CfgProjection(
        "plan-1",
        "snapshot-1",
        FlowGraph(blocks={}, entry_serial=0, func_ea=0),
        (block,),
    )
    prepared = PreparedCfgTransaction(attempt, projection, ("proof-a",))

    assert BoundCfgTransaction(
        prepared,
        session_id="session-1",
        bindings=((block, object()),),
    ).prepared == prepared
    with pytest.raises(ValueError, match="plan"):
        PreparedCfgTransaction(
            TransactionAttemptId("plan-2", "attempt-b"), projection
        )
    with pytest.raises(ValueError, match="duplicate"):
        BoundCfgTransaction(
            prepared,
            session_id="session-1",
            bindings=((block, object()), (block, object())),
        )


def test_projection_rejects_plan_refs_from_another_authority() -> None:
    """Plan-local focus refs stay within the projection's plan authority."""
    with pytest.raises(ValueError, match="authority"):
        CfgProjection(
            "plan-1",
            "snapshot-1",
            FlowGraph(blocks={}, entry_serial=0, func_ea=0),
            (PlanBlockRef("plan-2", "block-a"),),
        )


def test_bound_transaction_allows_same_authority_supporting_ref_outside_focus() -> None:
    """Focus refs guide projection and do not exhaust the binding manifest."""
    attempt = TransactionAttemptId("plan-1", "attempt-a")
    focus_ref = PlanBlockRef("plan-1", "block-a")
    prepared = PreparedCfgTransaction(
        attempt,
        CfgProjection(
            "plan-1",
            "snapshot-1",
            FlowGraph(blocks={}, entry_serial=0, func_ea=0),
            (focus_ref,),
        ),
    )

    supporting_ref = PlanBlockRef("plan-1", "supporting-block")

    assert BoundCfgTransaction(
        prepared,
        session_id="session-1",
        bindings=((supporting_ref, object()),),
    ).prepared == prepared


def test_bound_transaction_rejects_foreign_plan_authority_outside_focus() -> None:
    """Binding validates plan authority independently of focus."""
    prepared = PreparedCfgTransaction(
        TransactionAttemptId("plan-1", "attempt-a"),
        CfgProjection(
            "plan-1",
            "snapshot-1",
            FlowGraph(blocks={}, entry_serial=0, func_ea=0),
            (PlanBlockRef("plan-1", "block-a"),),
        ),
    )

    with pytest.raises(ValueError, match="authority"):
        BoundCfgTransaction(
            prepared,
            session_id="session-1",
            bindings=((PlanBlockRef("plan-2", "supporting-block"), object()),),
        )


def test_bound_transaction_allows_matching_logical_session() -> None:
    """Logical support refs bind when they belong to the bound session."""
    prepared = PreparedCfgTransaction(
        TransactionAttemptId("plan-1", "attempt-a"),
        CfgProjection(
            "plan-1",
            "snapshot-1",
            FlowGraph(blocks={}, entry_serial=0, func_ea=0),
        ),
    )
    logical_ref = LogicalBlockRef("session-1", "proxy-a", 0)

    assert BoundCfgTransaction(
        prepared,
        session_id="session-1",
        bindings=((logical_ref, object()),),
    ).prepared == prepared


def test_bound_transaction_rejects_foreign_logical_session() -> None:
    """A logical proxy cannot cross into a different bound session."""
    prepared = PreparedCfgTransaction(
        TransactionAttemptId("plan-1", "attempt-a"),
        CfgProjection(
            "plan-1",
            "snapshot-1",
            FlowGraph(blocks={}, entry_serial=0, func_ea=0),
        ),
    )

    with pytest.raises(ValueError, match="session authority"):
        BoundCfgTransaction(
            prepared,
            session_id="session-1",
            bindings=((LogicalBlockRef("session-2", "proxy-a", 0), object()),),
        )
    with pytest.raises(ValueError, match="session_id"):
        BoundCfgTransaction(prepared, session_id="")


def test_failure_phase_and_live_mutation_state_are_coupled() -> None:
    """Clean rejections and poisoned restarts have incompatible mutation states."""
    attempt = TransactionAttemptId("plan-1", "attempt-a")

    assert CfgTransactionFailure(
        attempt,
        CfgTransactionPhase.REJECTED_CLEAN,
        "preflight rejected",
        False,
    ).live_mutation_started is False
    with pytest.raises(ValueError, match="live_mutation_started"):
        CfgTransactionFailure(
            attempt,
            CfgTransactionPhase.POISONED_RESTART_REQUIRED,
            "partial write",
            False,
        )
