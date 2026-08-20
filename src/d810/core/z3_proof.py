"""Portable vocabulary for bounded Z3 proof outcomes.

The enums in this module are deliberately owned by :mod:`d810.core` so
portable observability events can describe proof outcomes without importing
the IDA-backed optimizer or prover layers.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Z3ProofStatus(str, Enum):
    """Classification of a bounded proof query."""

    PROVED = "proved"
    DISPROVED = "disproved"
    ABSTAINED = "abstained"


class Z3ProofAbstentionReason(str, Enum):
    """Why a bounded proof query could not be concluded."""

    NODE_LIMIT = "node_limit"
    TIMEOUT = "timeout"
    UNSUPPORTED_EXPRESSION = "unsupported_expression"
    SOLVER_UNKNOWN = "solver_unknown"


@dataclass(frozen=True, slots=True)
class Z3ProofFieldAuthority:
    """Default and inclusive bounds for one bounded proof option."""

    default: int
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        for field_name in ("default", "minimum", "maximum"):
            value = getattr(self, field_name)
            if type(value) is not int:
                raise TypeError(f"{field_name} must be an integer")
        if self.minimum > self.default or self.default > self.maximum:
            raise ValueError("proof field bounds must contain the default")


@dataclass(frozen=True, slots=True)
class Z3ProofPolicyAuthority:
    """Portable authority shared by runtime policy and pass editor fields."""

    max_expression_nodes: Z3ProofFieldAuthority
    proof_timeout_ms: Z3ProofFieldAuthority


Z3_PROOF_POLICY_AUTHORITY = Z3ProofPolicyAuthority(
    max_expression_nodes=Z3ProofFieldAuthority(
        default=256,
        minimum=1,
        maximum=4096,
    ),
    proof_timeout_ms=Z3ProofFieldAuthority(
        default=50,
        minimum=1,
        maximum=5000,
    ),
)


def get_z3_proof_policy_authority() -> Z3ProofPolicyAuthority:
    """Return the current portable proof-option authority."""

    return Z3_PROOF_POLICY_AUTHORITY


__all__ = [
    "Z3ProofAbstentionReason",
    "Z3ProofFieldAuthority",
    "Z3ProofPolicyAuthority",
    "Z3ProofStatus",
    "Z3_PROOF_POLICY_AUTHORITY",
    "get_z3_proof_policy_authority",
]
