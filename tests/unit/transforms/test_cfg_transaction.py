"""Contracts for portable CFG transaction references and authority."""

from __future__ import annotations

import inspect

import pytest

from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import (
    BoundCfgTransaction,
    CfgGenerationPoisoned,
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


def _attempt(
    *,
    plan_id: str = "plan-1",
    session_id: str = "session-1",
    generation: int = 3,
    attempt_id: str = "attempt-a",
) -> TransactionAttemptId:
    return TransactionAttemptId(
        plan_id=plan_id,
        session_id=session_id,
        generation=generation,
        attempt_id=attempt_id,
    )


def _projection(
    *,
    plan_id: str = "plan-1",
    focus_refs: tuple[object, ...] = (),
) -> CfgProjection:
    return CfgProjection(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        graph=FlowGraph(blocks={}, entry_serial=0, func_ea=0),
        focus_refs=focus_refs,
    )


def test_plan_local_refs_are_nominal_and_replay_stable() -> None:
    """Equal diagnostics cannot collapse distinct plan-local identities."""
    creation_intents = (
        (PlanBlockRef("plan-1", "block-a"), "body-digest:identical"),
        (PlanBlockRef("plan-1", "block-b"), "body-digest:identical"),
    )
    first, _first_digest = creation_intents[0]
    second, _second_digest = creation_intents[1]

    assert {digest for _ref, digest in creation_intents} == {
        "body-digest:identical"
    }
    assert len({ref for ref, _digest in creation_intents}) == 2
    assert first != second
    assert first == PlanBlockRef("plan-1", "block-a")


def test_attempt_identity_binds_plan_session_generation_and_attempt() -> None:
    """No attempt authority can be replayed into another live generation."""
    first = _attempt()

    assert first != _attempt(attempt_id="attempt-b")
    assert first != _attempt(generation=4)
    assert first != _attempt(session_id="session-2")
    assert first != _attempt(plan_id="plan-2")
    generated = TransactionAttemptId.new(
        plan_id="plan-1",
        session_id="session-1",
        generation=3,
    )
    assert generated.plan_id == "plan-1"
    assert generated.session_id == "session-1"
    assert generated.generation == 3
    assert generated.attempt_id


def test_plan_instruction_ref_requires_a_plan_block_ref() -> None:
    """Instruction-local identity is anchored by nominal plan authority."""
    block = PlanBlockRef("plan-1", "block-a")

    assert PlanInsnRef(block, "instruction-a").block == block
    with pytest.raises(TypeError, match="PlanBlockRef"):
        PlanInsnRef("block-a", "instruction-a")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("factory", "kwargs"),
    (
        (PlanBlockRef, {"plan_id": "", "local_block_id": "block-a"}),
        (PlanBlockRef, {"plan_id": "plan-1", "local_block_id": "   "}),
        (
            PlanInsnRef,
            {
                "block": PlanBlockRef("plan-1", "block-a"),
                "local_instruction_id": "",
            },
        ),
        (
            LogicalBlockRef,
            {"session_id": "", "proxy_token": "proxy-a", "version": 0},
        ),
        (
            LogicalBlockRef,
            {"session_id": "session-1", "proxy_token": "", "version": 0},
        ),
        (
            LogicalBlockRef,
            {"session_id": "session-1", "proxy_token": "proxy-a", "version": -1},
        ),
        (
            TransactionAttemptId,
            {
                "plan_id": "",
                "session_id": "session-1",
                "generation": 0,
                "attempt_id": "attempt-a",
            },
        ),
        (
            TransactionAttemptId,
            {
                "plan_id": "plan-1",
                "session_id": "",
                "generation": 0,
                "attempt_id": "attempt-a",
            },
        ),
        (
            TransactionAttemptId,
            {
                "plan_id": "plan-1",
                "session_id": "session-1",
                "generation": -1,
                "attempt_id": "attempt-a",
            },
        ),
        (
            TransactionAttemptId,
            {
                "plan_id": "plan-1",
                "session_id": "session-1",
                "generation": 0,
                "attempt_id": "",
            },
        ),
    ),
)
def test_nominal_reference_authority_rejects_blank_or_negative_values(
    factory: object,
    kwargs: dict[str, object],
) -> None:
    """Portable authority cannot contain blank IDs or negative generations."""
    with pytest.raises((TypeError, ValueError)):
        factory(**kwargs)  # type: ignore[operator]


def test_reference_constructors_expose_no_live_or_diagnostic_shortcuts() -> None:
    """Portable reference identity cannot be constructed from live coordinates."""
    forbidden = {"ea", "badaddr", "body_hash", "serial", "snapshot_block"}
    for ref_type in (PlanBlockRef, PlanInsnRef, NativeBlockRef, LogicalBlockRef):
        assert not (forbidden & set(inspect.signature(ref_type).parameters))


def test_cfg_projection_contains_only_portable_graph_and_references() -> None:
    """Projection authority has no callback, SDK object, or live-serial input."""
    block = PlanBlockRef("plan-1", "block-a")
    projection = _projection(focus_refs=(block,))

    assert projection.focus_refs == (block,)
    assert not {
        "mba",
        "mblock",
        "callback",
        "mutation",
        "live_serial",
    }.intersection(inspect.signature(CfgProjection).parameters)
    with pytest.raises(TypeError, match="FlowGraph"):
        CfgProjection("plan-1", "snapshot-1", object())  # type: ignore[arg-type]


def test_projection_rejects_plan_refs_from_another_authority() -> None:
    """Plan-local focus refs stay within the projection's plan authority."""
    with pytest.raises(ValueError, match="authority"):
        _projection(focus_refs=(PlanBlockRef("plan-2", "block-a"),))


def test_transactions_keep_attempt_projection_and_binding_authority_consistent() -> None:
    """Prepared and bound records reject cross-authority reuse."""
    block = PlanBlockRef("plan-1", "block-a")
    projection = _projection(focus_refs=(block,))
    prepared = PreparedCfgTransaction(_attempt(), projection, ("proof-a",))

    assert BoundCfgTransaction(
        prepared,
        session_id="session-1",
        generation=3,
        bindings=((block, object()),),
    ).prepared == prepared
    with pytest.raises(ValueError, match="plan"):
        PreparedCfgTransaction(_attempt(plan_id="plan-2"), projection)
    with pytest.raises(ValueError, match="session"):
        BoundCfgTransaction(
            prepared,
            session_id="session-2",
            generation=3,
        )
    with pytest.raises(ValueError, match="generation"):
        BoundCfgTransaction(
            prepared,
            session_id="session-1",
            generation=4,
        )
    with pytest.raises(ValueError, match="duplicate"):
        BoundCfgTransaction(
            prepared,
            session_id="session-1",
            generation=3,
            bindings=((block, object()), (block, object())),
        )


def test_bound_transaction_allows_same_authority_supporting_ref_outside_focus() -> None:
    """Focus refs guide projection and do not exhaust the binding manifest."""
    prepared = PreparedCfgTransaction(
        _attempt(),
        _projection(focus_refs=(PlanBlockRef("plan-1", "block-a"),)),
    )
    supporting_ref = PlanBlockRef("plan-1", "supporting-block")

    assert BoundCfgTransaction(
        prepared,
        session_id="session-1",
        generation=3,
        bindings=((supporting_ref, object()),),
    ).prepared == prepared


def test_bound_transaction_rejects_foreign_reference_authority() -> None:
    """Neither a plan ref nor a logical proxy may cross authority boundaries."""
    prepared = PreparedCfgTransaction(_attempt(), _projection())

    with pytest.raises(ValueError, match="plan authority"):
        BoundCfgTransaction(
            prepared,
            session_id="session-1",
            generation=3,
            bindings=((PlanBlockRef("plan-2", "supporting-block"), object()),),
        )
    with pytest.raises(ValueError, match="session authority"):
        BoundCfgTransaction(
            prepared,
            session_id="session-1",
            generation=3,
            bindings=((LogicalBlockRef("session-2", "proxy-a", 0), object()),),
        )


def test_projection_failure_records_that_live_mutation_never_started() -> None:
    """A pure projection rejection cannot masquerade as a rollback."""
    failure = CfgTransactionFailure(
        attempt_id=_attempt(),
        phase=CfgTransactionPhase.REJECTED_CLEAN,
        reason="projection rejected",
        live_mutation_started=False,
        first_failed_obligation="operation:route-a",
        failure_phase="projection",
    )

    assert failure.live_mutation_started is False
    assert failure.failure_phase == "projection"
    with pytest.raises(ValueError, match="live_mutation_started"):
        CfgTransactionFailure(
            attempt_id=_attempt(),
            phase=CfgTransactionPhase.POISONED_RESTART_REQUIRED,
            reason="partial write",
            live_mutation_started=False,
        )
    with pytest.raises(ValueError, match="poisoned"):
        CfgGenerationPoisoned(failure)
