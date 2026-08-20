"""Typed receipts for the generic bounded Z3 predicate transforms."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from d810.core.observability_events import Z3PredicateProofObserved
from d810.core.z3_proof import Z3ProofAbstentionReason, Z3ProofStatus


def _event(**overrides: object) -> Z3PredicateProofObserved:
    values: dict[str, object] = {
        "func_ea": 0x401000,
        "transform_id": "z-3-setz-generic",
        "operation": "prove_equal",
        "max_expression_nodes": 256,
        "proof_timeout_ms": 50,
        "observed_expression_nodes": 7,
        "elapsed_ms": 1.25,
        "status": Z3ProofStatus.PROVED,
        "reason": None,
    }
    values.update(overrides)
    return Z3PredicateProofObserved(**values)


def test_z3_predicate_receipt_carries_policy_observation_and_is_immutable() -> None:
    event = _event()

    assert event.transform_id == "z-3-setz-generic"
    assert event.max_expression_nodes == 256
    assert event.proof_timeout_ms == 50
    assert event.observed_expression_nodes == 7
    assert event.elapsed_ms == pytest.approx(1.25)
    assert event.status is Z3ProofStatus.PROVED
    assert event.reason is None

    with pytest.raises(FrozenInstanceError):
        event.status = "abstained"  # type: ignore[misc]


@pytest.mark.parametrize("status", tuple(Z3ProofStatus))
def test_z3_predicate_receipt_accepts_each_result_status(
    status: Z3ProofStatus,
) -> None:
    event = _event(
        status=status,
        reason=(
            None
            if status is not Z3ProofStatus.ABSTAINED
            else Z3ProofAbstentionReason.NODE_LIMIT
        ),
    )

    assert event.status is status


@pytest.mark.parametrize("reason", tuple(Z3ProofAbstentionReason))
def test_z3_predicate_receipt_preserves_each_typed_abstention_reason(
    reason: Z3ProofAbstentionReason,
) -> None:
    event = _event(
        status=Z3ProofStatus.ABSTAINED,
        reason=reason,
    )

    assert event.reason is reason


def test_z3_predicate_receipt_requires_reason_for_abstention() -> None:
    with pytest.raises(ValueError, match="reason"):
        _event(status=Z3ProofStatus.ABSTAINED, reason=None)


def test_z3_predicate_receipt_rejects_synthetic_reason_for_conclusive_result() -> None:
    with pytest.raises(ValueError, match="reason"):
        _event(status=Z3ProofStatus.PROVED, reason=Z3ProofAbstentionReason.TIMEOUT)


def test_z3_predicate_receipt_rejects_plain_status_strings() -> None:
    with pytest.raises(TypeError, match="status"):
        _event(status="proved")


def test_z3_predicate_receipt_rejects_unknown_abstention_reasons() -> None:
    with pytest.raises(TypeError, match="reason"):
        _event(status=Z3ProofStatus.ABSTAINED, reason="unknown")
