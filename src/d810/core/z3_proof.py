"""Portable vocabulary for bounded Z3 proof outcomes.

The enums in this module are deliberately owned by :mod:`d810.core` so
portable observability events can describe proof outcomes without importing
the IDA-backed optimizer or prover layers.
"""

from __future__ import annotations

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


__all__ = ["Z3ProofAbstentionReason", "Z3ProofStatus"]
