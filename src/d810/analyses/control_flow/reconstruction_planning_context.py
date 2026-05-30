"""Portable reconstruction-planning request/result dataclasses (dissolution, llr-lyly).

These plain dataclasses describe the *request* (``ReconstructionPlanningContext``),
the emission-mode labels (``ReconstructionEmissionMode``), and the planner *result*
(``ReconstructionPlanningDecision``).  They are portable (no transforms / IDA deps)
so a read-only analyses module (``reconstruction_candidate_builder``) can reference
them without importing the transforms-bound planner.  The concrete planner
``plan_reconstruction_candidate`` (which CONSTRUCTS these and lives in the
transforms layer) is injected at call time.
"""
from __future__ import annotations

from dataclasses import dataclass


class ReconstructionEmissionMode:
    """Labels for reconstruction emission decisions."""

    DIRECT = "direct"
    CONDITIONAL_ARM = "conditional_arm"
    PRED_SPLIT = "pred_split"


@dataclass(frozen=True, slots=True)
class ReconstructionPlanningContext:
    """Structured request from Hodur into CFG reconstruction planning."""

    ordered_path: tuple[int, ...]
    horizon_block: int
    target_entry: int
    source_anchor_block: int
    source_branch_arm: int | None
    is_conditional_transition: bool
    shared_suffix_blocks: frozenset[int]
    dispatcher_region: frozenset[int]
    has_unsafe_trailing_insns: bool


@dataclass(frozen=True, slots=True)
class ReconstructionPlanningDecision:
    """Planner result for a reconstructed semantic corridor candidate."""

    accepted: bool
    target_entry: int | None = None
    emission_mode: str | None = None
    first_shared_block: int | None = None
    via_pred: int | None = None
    rejection_reason: str = ""


__all__ = [
    "ReconstructionEmissionMode",
    "ReconstructionPlanningContext",
    "ReconstructionPlanningDecision",
]
