"""OpcodeDistributionCollector - instruction opcode frequency histogram.

Fires at MMAT_PREOPTIMIZED (5). Accepts FlowGraph (unit tests) or
live mba_t (IDA runtime).

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

from d810.recon.models import CandidateFlag, ReconResult

_MMAT_PREOPTIMIZED = 5
_DOMINANCE_THRESHOLD = 0.5


class OpcodeDistributionCollector:
    """Collect opcode frequency metrics from microcode at MMAT_PREOPTIMIZED."""

    name: str = "OpcodeDistributionCollector"
    maturities: frozenset[int] = frozenset({_MMAT_PREOPTIMIZED})
    level: str = "microcode"

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        counter: Counter[int] = Counter()

        if hasattr(target, "blocks") and hasattr(target, "entry_serial"):
            # FlowGraph path
            for blk in target.blocks.values():
                for insn in getattr(blk, "insn_snapshots", ()):
                    counter[int(insn.opcode)] += 1
        else:
            # Live mba_t path
            qty = int(getattr(target, "qty", 0) or 0)
            for i in range(qty):
                blk = target.get_mblock(i)
                if blk is None:
                    continue
                insn = getattr(blk, "head", None)
                while insn is not None:
                    counter[int(getattr(insn, "opcode", 0))] += 1
                    insn = getattr(insn, "next", None)

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
