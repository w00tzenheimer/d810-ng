"""OpcodeDistributionCollector - instruction opcode frequency histogram.

Fires at MMAT_PREOPTIMIZED (5). Consumes a portable ``d810.ir`` FlowGraph
only -- the HIGH layer lifts the live ``mba`` once at the FLOWGRAPH_READY
boundary (E4a) and hands collectors the snapshot, so this is data-model
portable (no live ``mba_t`` / ``mblock_t`` duck-typing; ticket llr-zeyu).

Metrics produced:
    - ``total_insns``: total instruction count across all blocks
    - ``unique_opcodes``: number of distinct opcodes
    - ``top_opcode``: most frequent opcode integer (-1 if empty)
    - ``top_opcode_count``: count of top opcode
    - ``top_opcode_ratio``: fraction of total instructions with top opcode

Candidates:
    - ``"high_opcode_dominance"`` when top_opcode_ratio > 0.5
"""
from __future__ import annotations

import time
from collections import Counter
from types import MappingProxyType

from d810.analyses.control_flow.models import CandidateFlag, ReconResult

_MMAT_PREOPTIMIZED = 5
_DOMINANCE_THRESHOLD = 0.5


class OpcodeDistributionCollector:
    """Collect opcode frequency metrics from microcode at MMAT_PREOPTIMIZED."""

    name: str = "OpcodeDistributionCollector"
    maturities: frozenset[int] = frozenset({_MMAT_PREOPTIMIZED})
    level: str = "microcode"

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        # ``target`` is a portable d810.ir FlowGraph; iterate its block
        # snapshots only -- no live mba / mblock duck-typing (llr-zeyu).
        counter: Counter[int] = Counter()
        for blk in target.blocks.values():
            for insn in blk.insn_snapshots:
                counter[int(insn.opcode)] += 1

        total = sum(counter.values())
        unique = len(counter)

        if counter:
            top_opcode, top_count = counter.most_common(1)[0]
            top_ratio = float(top_count) / float(total) if total > 0 else 0.0
        else:
            top_opcode, top_count, top_ratio = -1, 0, 0.0

        metrics = MappingProxyType({
            "total_insns": total,
            "unique_opcodes": unique,
            "top_opcode": top_opcode,
            "top_opcode_count": top_count,
            "top_opcode_ratio": top_ratio,
        })

        candidates: list[CandidateFlag] = []
        if top_ratio > _DOMINANCE_THRESHOLD and total > 0:
            candidates.append(CandidateFlag(
                kind="high_opcode_dominance",
                block_serial=-1,
                confidence=min(1.0, top_ratio),
                detail=f"opcode {top_opcode} dominates {top_ratio:.1%} of {total} insns",
            ))

        return ReconResult(
            collector_name=self.name,
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=time.time(),
            metrics=metrics,
            candidates=tuple(candidates),
        )
