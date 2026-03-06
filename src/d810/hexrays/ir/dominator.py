"""Hex-Rays compatibility shims for dominator analysis over live ``mba_t``."""
from __future__ import annotations

from d810.core.typing import Any

from d810.cfg.dominator import compute_dom_tree, dominates


def _successors_from_mba(mba: Any) -> dict[int, list[int]]:
    num_blocks = int(getattr(mba, "qty", 0) or 0)
    successors: dict[int, list[int]] = {i: [] for i in range(num_blocks)}

    direct_successors_available = True
    for i in range(num_blocks):
        blk = mba.get_mblock(i)
        if hasattr(blk, "nsucc") and hasattr(blk, "succ"):
            nsucc = int(blk.nsucc())
            successors[i] = [int(blk.succ(j)) for j in range(nsucc)]
        elif hasattr(blk, "succset"):
            successors[i] = [int(s) for s in blk.succset]
        else:
            direct_successors_available = False
            break

    if direct_successors_available:
        return successors

    successors = {i: [] for i in range(num_blocks)}
    for i in range(num_blocks):
        blk = mba.get_mblock(i)
        for pred in getattr(blk, "predset", ()):
            pred_int = int(pred)
            if 0 <= pred_int < num_blocks:
                successors[pred_int].append(i)
    return successors


def compute_dominators(mba: Any) -> list[set[int]]:
    """Compatibility wrapper returning dominator sets for MBA-like inputs."""
    num_blocks = int(getattr(mba, "qty", 0) or 0)
    if num_blocks == 0:
        return []

    tree = compute_dom_tree(_successors_from_mba(mba), entry=0)
    doms: list[set[int]] = []
    for node in range(num_blocks):
        doms.append(set(tree.dominators_of(node)))
    return doms


__all__ = ["compute_dominators", "dominates"]
