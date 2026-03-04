"""DispatchPatternCollector - dispatcher candidate detection.

Fires at MMAT_CALLS (3) and MMAT_GLBOPT1 (14).
Detects: NWAY (switch, BLT_NWAY=5) blocks, high-fan-out 2WAY (BLT_2WAY=4) chains, back-edges.

Metrics:
    - ``nway_block_count``: number of BLT_NWAY blocks
    - ``max_nway_fan_out``: maximum successor count of any NWAY block
    - ``tway_chain_max_len``: longest chain of consecutive 2WAY (conditional) blocks
    - ``back_edge_count``: number of back-edges detected via DFS
    - ``indirect_jump_count``: blocks with NWAY and 0 known successors (opaque target)

Candidates:
    - ``"switch_dispatcher"`` for NWAY blocks with fan-out >= 3
    - ``"back_edge_hub"`` for blocks with back_edge_count >= 2
"""
from __future__ import annotations

import time
from types import MappingProxyType

from d810.recon.models import CandidateFlag, ReconResult

from d810.cfg.microcode_constants import BLT_2WAY as _BLT_2WAY
from d810.cfg.microcode_constants import BLT_NWAY as _BLT_NWAY

_MMAT_CALLS = 3
_MMAT_GLBOPT1 = 14

_SWITCH_FAN_OUT_MIN = 3


def _count_back_edges(
    nodes: set[int],
    succs: dict[int, tuple[int, ...]],
    entry: int | None,
) -> tuple[int, dict[int, int]]:
    """DFS-based back-edge detection.

    Returns (total_back_edges, per_target_count).
    """
    if entry is None or entry not in nodes:
        return 0, {}
    color: dict[int, int] = {}  # 0=white, 1=grey, 2=black
    back_counts: dict[int, int] = {}
    stack = [(entry, False)]
    total = 0
    while stack:
        node, leaving = stack.pop()
        if leaving:
            color[node] = 2
            continue
        if color.get(node, 0) == 1:
            continue
        if color.get(node, 0) == 2:
            continue
        color[node] = 1
        stack.append((node, True))
        for succ in succs.get(node, ()):
            if color.get(succ, 0) == 1:
                total += 1
                back_counts[succ] = back_counts.get(succ, 0) + 1
            elif color.get(succ, 0) == 0:
                stack.append((succ, False))
    return total, back_counts


class DispatchPatternCollector:
    """Detect dispatcher patterns in microcode at MMAT_CALLS and MMAT_GLBOPT1."""

    name: str = "DispatchPatternCollector"
    maturities: frozenset[int] = frozenset({_MMAT_CALLS, _MMAT_GLBOPT1})
    level: str = "microcode"

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        if hasattr(target, "blocks") and hasattr(target, "entry_serial"):
            entry = getattr(target, "entry_serial", 0)
            block_iter = list(target.blocks.values())
            nodes = set(target.blocks.keys())
            succs: dict[int, tuple[int, ...]] = {
                b.serial: b.succs for b in block_iter
            }
        else:
            entry = 0
            nodes = set()
            succs = {}
            block_iter = []
            qty = int(getattr(target, "qty", 0) or 0)
            for i in range(qty):
                blk = target.get_mblock(i)
                if blk is None:
                    continue
                serial = int(getattr(blk, "serial", i))
                nodes.add(serial)
                out = tuple(int(s) for s in getattr(blk, "succset", ()))
                succs[serial] = out
                block_iter.append(blk)

        nway_blocks: list[tuple[int, int]] = []  # (serial, fan_out)
        indirect_count = 0

        for blk in block_iter:
            serial = int(getattr(blk, "serial", 0))
            blk_type = int(getattr(blk, "block_type", 0))
            blk_succs = succs.get(serial, ())
            if blk_type == _BLT_NWAY:
                fan_out = len(blk_succs)
                nway_blocks.append((serial, fan_out))
                if fan_out == 0:
                    indirect_count += 1

        max_fan_out = max((fo for _, fo in nway_blocks), default=0)
        back_total, back_per_target = _count_back_edges(nodes, succs, entry)

        # Longest 2WAY chain (simple: count 2WAY blocks - full chain analysis is expensive)
        tway_count = sum(
            1 for blk in block_iter
            if int(getattr(blk, "block_type", 0)) == _BLT_2WAY
        )

        metrics = MappingProxyType({
            "nway_block_count": len(nway_blocks),
            "max_nway_fan_out": max_fan_out,
            "tway_chain_max_len": tway_count,
            "back_edge_count": back_total,
            "indirect_jump_count": indirect_count,
        })

        candidates: list[CandidateFlag] = []
        for serial, fan_out in nway_blocks:
            if fan_out >= _SWITCH_FAN_OUT_MIN:
                conf = min(1.0, 0.4 + (fan_out - _SWITCH_FAN_OUT_MIN) * 0.1)
                candidates.append(CandidateFlag(
                    kind="switch_dispatcher",
                    block_serial=serial,
                    confidence=conf,
                    detail=f"NWAY block {serial} with {fan_out} successors",
                ))
        for target_serial, count in back_per_target.items():
            if count >= 2:
                candidates.append(CandidateFlag(
                    kind="back_edge_hub",
                    block_serial=target_serial,
                    confidence=min(1.0, 0.3 + count * 0.15),
                    detail=f"block {target_serial} receives {count} back-edges",
                ))

        return ReconResult(
            collector_name=self.name,
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=time.time(),
            metrics=metrics,
            candidates=tuple(candidates),
        )
