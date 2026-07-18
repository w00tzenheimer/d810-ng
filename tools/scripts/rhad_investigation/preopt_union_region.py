"""Compatibility re-exports for the production PREOPT union planner."""

from d810.analyses.control_flow.preopt_union_region import (
    PreoptUnionAbstention,
    PreoptUnionAbstentionReason,
    PreoptUnionRegionPlan,
    plan_preopt_union_region,
    select_missing_preopt_union_region,
)

__all__ = [
    "PreoptUnionAbstention",
    "PreoptUnionAbstentionReason",
    "PreoptUnionRegionPlan",
    "plan_preopt_union_region",
    "select_missing_preopt_union_region",
]
