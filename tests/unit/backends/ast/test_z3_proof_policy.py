"""Portable policy and resource-accounting tests for bounded AST proofs."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass, is_dataclass

import pytest


def test_proof_policy_defaults_are_immutable_and_portable() -> None:
    from d810.backends.ast.z3_proof_policy import Z3ProofPolicy

    policy = Z3ProofPolicy()

    assert is_dataclass(policy)
    assert policy.max_expression_nodes == 256
    assert policy.proof_timeout_ms == 50
    assert not hasattr(policy, "__dict__")

    with pytest.raises(FrozenInstanceError):
        policy.max_expression_nodes = 128  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_expression_nodes", 0),
        ("max_expression_nodes", 4097),
        ("proof_timeout_ms", 0),
        ("proof_timeout_ms", 5001),
        ("max_expression_nodes", True),
        ("proof_timeout_ms", False),
    ),
)
def test_proof_policy_rejects_values_outside_exact_ranges(
    field: str, value: object
) -> None:
    from d810.backends.ast.z3_proof_policy import Z3ProofPolicy

    with pytest.raises((TypeError, ValueError), match=field):
        Z3ProofPolicy(**{field: value})


def test_proof_outcome_types_are_string_enums_and_frozen() -> None:
    from d810.backends.ast.z3_proof_policy import (
        Z3ProofAbstentionReason,
        Z3ProofResult,
        Z3ProofStatus,
    )

    assert Z3ProofStatus.PROVED.value == "proved"
    assert Z3ProofStatus.DISPROVED.value == "disproved"
    assert Z3ProofStatus.ABSTAINED.value == "abstained"
    assert Z3ProofAbstentionReason.NODE_LIMIT.value == "node_limit"
    assert Z3ProofAbstentionReason.TIMEOUT.value == "timeout"
    assert (
        Z3ProofAbstentionReason.UNSUPPORTED_EXPRESSION.value
        == "unsupported_expression"
    )
    assert Z3ProofAbstentionReason.SOLVER_UNKNOWN.value == "solver_unknown"

    result = Z3ProofResult(
        status=Z3ProofStatus.ABSTAINED,
        reason=Z3ProofAbstentionReason.NODE_LIMIT,
        observed_expression_nodes=4,
        elapsed_ms=0.25,
    )
    assert is_dataclass(result)
    assert not hasattr(result, "__dict__")
    with pytest.raises(FrozenInstanceError):
        result.status = Z3ProofStatus.PROVED  # type: ignore[misc]


@dataclass(frozen=True, slots=True)
class _FakeExpression:
    kind: str
    children: tuple["_FakeExpression", ...] = ()


def _expand_with_budget(node: _FakeExpression, budget) -> dict[str, object]:
    """A production-shaped pre-order walker used to exercise the budget contract."""

    budget.consume()
    return {
        "kind": node.kind,
        "children": tuple(_expand_with_budget(child, budget) for child in node.children),
    }


def test_budget_counts_repeated_occurrences_not_dag_identity() -> None:
    from d810.backends.ast.z3_proof_policy import (
        Z3ExpressionNodeBudget,
        Z3ProofPolicy,
    )

    shared_leaf = _FakeExpression("leaf")
    expression = _FakeExpression(
        "operator",
        (shared_leaf, _FakeExpression("operator", (shared_leaf,))),
    )
    budget = Z3ExpressionNodeBudget(Z3ProofPolicy(max_expression_nodes=5))

    expanded = _expand_with_budget(expression, budget)

    assert expanded["kind"] == "operator"
    assert budget.observed_nodes == 4


def test_budget_aborts_before_constructing_the_oversized_occurrence() -> None:
    from d810.backends.ast.z3_proof_policy import (
        Z3ExpressionNodeBudget,
        Z3NodeLimitExceeded,
        Z3ProofPolicy,
    )

    expression = _FakeExpression(
        "operator",
        (
            _FakeExpression("constant"),
            _FakeExpression("leaf"),
        ),
    )
    budget = Z3ExpressionNodeBudget(Z3ProofPolicy(max_expression_nodes=2))

    with pytest.raises(Z3NodeLimitExceeded):
        _expand_with_budget(expression, budget)

    assert budget.observed_nodes == 2
