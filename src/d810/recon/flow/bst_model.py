from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from d810.core.typing import Dict
from d810.core.typing import Optional
from d810.core.typing import Set
from d810.core.typing import Tuple


@dataclass
class BSTAnalysisResult:
    """Semantic model for BST dispatcher analysis results."""

    handler_state_map: Dict[int, int] = field(default_factory=dict)
    handler_range_map: Dict[int, Tuple[Optional[int], Optional[int]]] = field(
        default_factory=dict
    )
    transitions: Dict[int, Optional[int]] = field(default_factory=dict)
    conditional_transitions: Dict[int, Set[int]] = field(default_factory=dict)
    exits: Set[int] = field(default_factory=set)
    pre_header_serial: Optional[int] = None
    initial_state: Optional[int] = None
    bst_node_blocks: Set[int] = field(default_factory=set)


def resolve_target_via_bst(
    bst_result: BSTAnalysisResult,
    state_value: int,
) -> Optional[int]:
    """Resolve a concrete state value to a handler block serial."""
    for handler_serial, state_const in bst_result.handler_state_map.items():
        if state_const == state_value:
            return handler_serial

    exact_handler_serials = set(bst_result.handler_state_map.keys())
    for handler_serial, (low, high) in bst_result.handler_range_map.items():
        if handler_serial in exact_handler_serials:
            continue
        if (
            low is not None
            and high is not None
            and (high - low) >= 0xFFFF0000
        ):
            continue
        if low is not None and state_value < low:
            continue
        if high is not None and state_value > high:
            continue
        return handler_serial

    return None


__all__ = ["BSTAnalysisResult", "resolve_target_via_bst"]
