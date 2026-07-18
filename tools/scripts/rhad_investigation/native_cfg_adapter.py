"""Compatibility re-exports for the production native CFG adapter."""

from d810.analyses.control_flow.native_cfg_adapter import (
    NativeFlowBlockFact,
    build_native_cfg_from_flow_facts,
    can_decode_proven_native_successor,
    has_native_semantic_boundary,
    is_native_direct_control_operand,
    needs_native_flow_decode,
    select_visited_native_flow_facts,
    traversable_native_successor_eas,
)

__all__ = [
    "NativeFlowBlockFact",
    "build_native_cfg_from_flow_facts",
    "can_decode_proven_native_successor",
    "has_native_semantic_boundary",
    "is_native_direct_control_operand",
    "needs_native_flow_decode",
    "select_visited_native_flow_facts",
    "traversable_native_successor_eas",
]
