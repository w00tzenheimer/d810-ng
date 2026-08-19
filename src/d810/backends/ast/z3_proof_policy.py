"""Portable policy and outcome models for bounded AST-level Z3 proofs.

This module deliberately has no IDA or Z3 dependency.  The runtime prover in
``d810.backends.ast.z3`` consumes these values, while configuration and pure
tests can use them without importing the IDA provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Z3ProofStatus(str, Enum):
    """Classification of a proof query."""

    PROVED = "proved"
    DISPROVED = "disproved"
    ABSTAINED = "abstained"


class Z3ProofAbstentionReason(str, Enum):
    """Why a proof query could not be concluded."""

    NODE_LIMIT = "node_limit"
    TIMEOUT = "timeout"
    UNSUPPORTED_EXPRESSION = "unsupported_expression"
    SOLVER_UNKNOWN = "solver_unknown"


@dataclass(frozen=True, slots=True)
class Z3ProofPolicy:
    """Immutable resource limits for one generic predicate proof."""

    max_expression_nodes: int = 256
    proof_timeout_ms: int = 50

    def __post_init__(self) -> None:
        _validate_bounded_integer(
            "max_expression_nodes", self.max_expression_nodes, minimum=1, maximum=4096
        )
        _validate_bounded_integer(
            "proof_timeout_ms", self.proof_timeout_ms, minimum=1, maximum=5000
        )


@dataclass(frozen=True, slots=True)
class Z3ProofResult:
    """Portable result receipt returned by a bounded proof query."""

    status: Z3ProofStatus
    reason: Z3ProofAbstentionReason | None
    observed_expression_nodes: int | None
    elapsed_ms: float


class Z3NodeLimitExceeded(RuntimeError):
    """Internal signal raised before constructing an over-budget occurrence."""

    def __init__(self, *, observed_nodes: int, limit: int) -> None:
        self.observed_nodes = observed_nodes
        self.limit = limit
        super().__init__(
            "Z3 expression node limit exhausted "
            f"after {observed_nodes} nodes (limit {limit})"
        )


class Z3ExpressionNodeBudget:
    """Mutable per-expansion occurrence budget.

    The budget is intentionally not part of the frozen policy.  A new budget
    is created for each translation, and ``consume`` must be called before the
    caller constructs or descends into an occurrence.
    """

    __slots__ = ("_limit", "_observed_nodes", "_charged_occurrences")

    def __init__(self, policy: Z3ProofPolicy | int) -> None:
        if isinstance(policy, Z3ProofPolicy):
            limit = policy.max_expression_nodes
        else:
            limit = policy
        _validate_bounded_integer("max_expression_nodes", limit, minimum=1, maximum=4096)
        self._limit = limit
        self._observed_nodes = 0
        # The AST builder consumes occurrences before it constructs them.  The
        # visitor later sees those same objects, so retain the objects
        # themselves until this query ends.  A strong reference is important:
        # an integer ``id()`` can be reused after an object dies, which would
        # let an unrelated replacement occurrence consume a stale charge.
        # Repeated references preserve occurrence multiplicity without relying
        # on object equality or hashing.
        self._charged_occurrences: list[object] = []

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def observed_nodes(self) -> int:
        """Number of occurrences successfully consumed so far."""

        return self._observed_nodes

    @property
    def observed_expression_nodes(self) -> int:
        """Descriptive alias used by proof result receipts."""

        return self._observed_nodes

    def consume(self) -> None:
        """Consume one occurrence, raising before it can be constructed."""

        if self._observed_nodes >= self._limit:
            raise Z3NodeLimitExceeded(
                observed_nodes=self._observed_nodes,
                limit=self._limit,
            )
        self._observed_nodes += 1

    @staticmethod
    def _unwrap_occurrence(occurrence: object) -> object:
        """Unwrap AST proxies while preserving object identity semantics."""

        target = occurrence
        # AstProxy deliberately keeps its target private while forwarding the
        # AST interface.  Unwrap one or more proxy layers without importing the
        # IDA-specific AST implementation into this portable module.
        while hasattr(target, "_target"):
            next_target = getattr(target, "_target")
            if next_target is target:
                break
            target = next_target
        return target

    def mark_charged(self, occurrence: object) -> None:
        """Record an occurrence already consumed at the builder seam."""

        self._charged_occurrences.append(self._unwrap_occurrence(occurrence))

    def consume_ast(self, occurrence: object) -> None:
        """Consume an AST occurrence unless its builder charge is recorded."""

        target = self._unwrap_occurrence(occurrence)
        for index, charged in enumerate(self._charged_occurrences):
            if charged is target:
                del self._charged_occurrences[index]
                return
        self.consume()


# Short aliases keep the primitive convenient for backend-local callers while
# the descriptive names above remain the public portable vocabulary.
ExpressionNodeBudget = Z3ExpressionNodeBudget
NodeLimitExceeded = Z3NodeLimitExceeded


def _validate_bounded_integer(
    field_name: str, value: object, *, minimum: int, maximum: int
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{field_name} must be an integer in {minimum}..{maximum}; "
            f"got {value!r}"
        )
    if value < minimum or value > maximum:
        raise ValueError(
            f"{field_name} must be an integer in {minimum}..{maximum}; "
            f"got {value!r}"
        )


__all__ = [
    "ExpressionNodeBudget",
    "NodeLimitExceeded",
    "Z3ExpressionNodeBudget",
    "Z3NodeLimitExceeded",
    "Z3ProofAbstentionReason",
    "Z3ProofPolicy",
    "Z3ProofResult",
    "Z3ProofStatus",
]
