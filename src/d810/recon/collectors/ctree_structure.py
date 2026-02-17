"""CtreeStructureCollector — ctree-level structural metrics.

Fires at CMAT_FINAL (60). Walks the ctree using duck-typed iteration
(``cfunc.body`` and child iteration). Works with both real ``cfunc_t``
objects (IDA runtime) and stub objects (unit tests).

Metrics:
    - ``switch_count``: number of switch statements
    - ``switch_max_arms``: maximum case count in any switch
    - ``if_count``: number of if statements
    - ``goto_count``: number of goto statements
    - ``max_nesting_depth``: maximum nesting depth of if/switch
    - ``total_nodes``: total citem_t nodes visited

Candidates:
    - ``"large_switch"`` when switch_max_arms >= 5
    - ``"high_goto_density"`` when goto_count >= 3
"""
from __future__ import annotations

import time
from collections import deque
from types import MappingProxyType

from d810.recon.models import CandidateFlag, ReconResult

_CMAT_FINAL = 60

# cinsn_t op values (IDA SDK — duplicated to avoid IDA import)
_CIT_IF = 1
_CIT_SWITCH = 14
_CIT_GOTO = 17

_LARGE_SWITCH_THRESHOLD = 5
_HIGH_GOTO_THRESHOLD = 3


class CtreeStructureCollector:
    """Collect ctree structural metrics at CMAT_FINAL."""

    name: str = "CtreeStructureCollector"
    maturities: frozenset[int] = frozenset({_CMAT_FINAL})
    level: str = "ctree"

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        """Walk cfunc.body and collect structural counts.

        Accepts real ``ida_hexrays.cfunc_t`` or a stub with a ``.body``
        attribute that supports child iteration.
        """
        body = getattr(target, "body", None)
        if body is None:
            return self._empty_result(func_ea, maturity)

        switch_count = 0
        switch_max_arms = 0
        if_count = 0
        goto_count = 0
        total_nodes = 0
        max_depth = 0

        # BFS with depth tracking: queue entries are (node, depth)
        queue: deque[tuple[object, int]] = deque([(body, 0)])
        while queue:
            node, depth = queue.popleft()
            total_nodes += 1
            op = int(getattr(node, "op", -1))

            if op == _CIT_IF:
                if_count += 1
                if depth + 1 > max_depth:
                    max_depth = depth + 1
            elif op == _CIT_SWITCH:
                switch_count += 1
                arms = len(list(getattr(node, "children", [])))
                if arms > switch_max_arms:
                    switch_max_arms = arms
                if depth + 1 > max_depth:
                    max_depth = depth + 1
            elif op == _CIT_GOTO:
                goto_count += 1

            for child in getattr(node, "children", []):
                queue.append((child, depth + 1))

        metrics = MappingProxyType({
            "switch_count": switch_count,
            "switch_max_arms": switch_max_arms,
            "if_count": if_count,
            "goto_count": goto_count,
            "max_nesting_depth": max_depth,
            "total_nodes": total_nodes,
        })

        candidates: list[CandidateFlag] = []
        if switch_max_arms >= _LARGE_SWITCH_THRESHOLD:
            candidates.append(CandidateFlag(
                kind="large_switch",
                block_serial=-1,
                confidence=min(1.0, 0.4 + (switch_max_arms - _LARGE_SWITCH_THRESHOLD) * 0.05),
                detail=f"switch with {switch_max_arms} arms",
            ))
        if goto_count >= _HIGH_GOTO_THRESHOLD:
            candidates.append(CandidateFlag(
                kind="high_goto_density",
                block_serial=-1,
                confidence=min(1.0, 0.3 + goto_count * 0.1),
                detail=f"{goto_count} goto statements",
            ))

        return ReconResult(
            collector_name=self.name,
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=time.time(),
            metrics=metrics,
            candidates=tuple(candidates),
        )

    def _empty_result(self, func_ea: int, maturity: int) -> ReconResult:
        return ReconResult(
            collector_name=self.name,
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=time.time(),
            metrics=MappingProxyType({
                "switch_count": 0, "switch_max_arms": 0,
                "if_count": 0, "goto_count": 0,
                "max_nesting_depth": 0, "total_nodes": 0,
            }),
            candidates=(),
        )
