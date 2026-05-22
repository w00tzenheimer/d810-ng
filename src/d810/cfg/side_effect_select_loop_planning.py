"""CFG planning for side_effect_select_loop facts."""
from __future__ import annotations

from d810.cfg.graph_modification import DuplicateBlock, GraphModification, RedirectGoto
from d810.core.typing import Protocol, Sequence


class SideEffectSelectLoopFixLike(Protocol):
    init_block: int
    header_block: int
    per_pred_targets: Sequence[tuple[int, int]]
    terminal_redirects: Sequence[tuple[int, int, int]]


def build_side_effect_select_loop_modifications(
    fixes: Sequence[SideEffectSelectLoopFixLike],
) -> list[GraphModification]:
    """Translate side-effect selector-loop evidence into graph edits."""
    modifications: list[GraphModification] = []
    for fix in fixes:
        for pred, target in fix.per_pred_targets:
            modifications.append(
                DuplicateBlock(
                    source_block=int(fix.init_block),
                    target_block=int(target),
                    pred_serial=int(pred),
                    patch_kind="side_effect_select_loop",
                )
            )
        for src, old, new in fix.terminal_redirects:
            modifications.append(
                RedirectGoto(
                    from_serial=int(src),
                    old_target=int(old),
                    new_target=int(new),
                )
            )
    return modifications


__all__ = [
    "build_side_effect_select_loop_modifications",
]
