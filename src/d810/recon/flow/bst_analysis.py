from __future__ import annotations

from d810.core.typing import Any
from d810.core.typing import Optional
from d810.recon.flow.bst_model import BSTAnalysisResult
from d810.recon.flow.bst_model import resolve_target_via_bst


def _to_bst_result(raw: Any) -> BSTAnalysisResult:
    """Normalize extractor output to recon model."""
    return BSTAnalysisResult(
        handler_state_map=dict(getattr(raw, "handler_state_map", {}) or {}),
        handler_range_map=dict(getattr(raw, "handler_range_map", {}) or {}),
        transitions=dict(getattr(raw, "transitions", {}) or {}),
        conditional_transitions=dict(
            getattr(raw, "conditional_transitions", {}) or {}
        ),
        exits=set(getattr(raw, "exits", set()) or set()),
        pre_header_serial=getattr(raw, "pre_header_serial", None),
        initial_state=getattr(raw, "initial_state", None),
        bst_node_blocks=set(getattr(raw, "bst_node_blocks", set()) or set()),
    )


def analyze_bst_dispatcher(
    mba: Any,
    dispatcher_entry_serial: int,
    state_var_stkoff: Optional[int] = None,
    state_var_lvar_idx: Optional[int] = None,
    max_depth: int = 20,
) -> BSTAnalysisResult:
    """Analyze a BST dispatcher using the Hex-Rays extractor backend."""
    from d810.hexrays.utils.bst_analysis import analyze_bst_dispatcher as _analyze_bst_dispatcher

    raw = _analyze_bst_dispatcher(
        mba=mba,
        dispatcher_entry_serial=dispatcher_entry_serial,
        state_var_stkoff=state_var_stkoff,
        state_var_lvar_idx=state_var_lvar_idx,
        max_depth=max_depth,
    )
    return _to_bst_result(raw)


def find_bst_default_block(
    mba: Any,
    bst_root_serial: int,
    bst_node_blocks: set[int],
    handler_block_serials: set[int],
) -> Optional[int]:
    """Forward to the Hex-Rays extractor helper for BST default block lookup."""
    from d810.hexrays.utils.bst_analysis import (
        find_bst_default_block as _find_bst_default_block,
    )

    return _find_bst_default_block(
        mba=mba,
        bst_root_serial=bst_root_serial,
        bst_node_blocks=bst_node_blocks,
        handler_block_serials=handler_block_serials,
    )


__all__ = [
    "BSTAnalysisResult",
    "analyze_bst_dispatcher",
    "find_bst_default_block",
    "resolve_target_via_bst",
]
