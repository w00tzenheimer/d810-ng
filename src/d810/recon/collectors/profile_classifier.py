"""FlowProfileClassifierCollector - classify dispatch pattern in Recon.

Thin adapter wrapping ``FlowProfileClassifier`` into the ``ReconCollector``
protocol. Extracts structural components from the target (portable
``FlowGraph`` or live ``mba_t``), delegates classification to the existing
classifier, and packages the result as a ``ReconResult``.

Maturities fired: MMAT_CALLS (3), MMAT_GLBOPT1 (14).
"""
from __future__ import annotations

import time
from types import MappingProxyType

from d810.recon.flow.profile_classifier import FlowProfileClassifier
from d810.recon.models import CandidateFlag, ReconResult

_BLT_2WAY = 4
_BLT_NWAY = 5

_MMAT_CALLS = 3
_MMAT_GLBOPT1 = 14


def _portable_components(target) -> tuple[
    frozenset[int],
    frozenset[int],
    int,
    int,
    int,
    bool,
    dict[int, tuple[int, ...]],
]:
    """Extract classification components from a portable FlowGraph snapshot."""
    metadata = dict(getattr(target, "metadata", {}) or {})
    adj: dict[int, tuple[int, ...]] = {
        int(serial): tuple(int(s) for s in getattr(blk, "succs", ()))
        for serial, blk in target.blocks.items()
    }
    nodes = set(int(s) for s in target.blocks.keys())

    region = metadata.get("dispatch_region")
    if isinstance(region, (list, tuple, set, frozenset)):
        dispatch_region = frozenset(int(x) for x in region if int(x) in nodes)
    else:
        dispatch_region = frozenset(
            int(serial)
            for serial, blk in target.blocks.items()
            if int(getattr(blk, "block_type", 0)) == _BLT_NWAY
        )

    case_blocks = frozenset(nodes - set(dispatch_region))

    compare_chain_length = int(
        metadata.get(
            "compare_chain_length",
            sum(
                1
                for blk in target.blocks.values()
                if int(getattr(blk, "block_type", 0)) == _BLT_2WAY
            ),
        )
    )
    dispatch_table_size = int(
        metadata.get("dispatch_table_size", max(0, compare_chain_length))
    )
    state_alias_count = int(metadata.get("state_alias_count", 0))
    has_default = bool(metadata.get("has_default_target", False))

    return (
        dispatch_region,
        case_blocks,
        dispatch_table_size,
        compare_chain_length,
        state_alias_count,
        has_default,
        adj,
    )


def _live_components(target) -> tuple[
    frozenset[int],
    frozenset[int],
    int,
    int,
    int,
    bool,
    dict[int, tuple[int, ...]],
]:
    """Extract classification components from a live mba_t."""
    qty = int(getattr(target, "qty", 0) or 0)

    adj: dict[int, tuple[int, ...]] = {}
    nodes: set[int] = set()
    for i in range(qty):
        blk = target.get_mblock(i)
        if blk is None:
            continue
        serial = int(getattr(blk, "serial", i))
        nodes.add(serial)
        adj[serial] = tuple(int(s) for s in getattr(blk, "succset", ()))

    # Without dispatcher analysis, fall back to NWAY blocks as dispatch region
    dispatch_region = frozenset(
        serial for serial in nodes
        if serial in adj  # always true, but guard defensively
    )
    # Simplified: use NWAY detection when no blackboard
    nway_blocks: set[int] = set()
    for i in range(qty):
        blk = target.get_mblock(i)
        if blk is None:
            continue
        if int(getattr(blk, "type", 0)) == _BLT_NWAY:
            nway_blocks.add(int(getattr(blk, "serial", i)))

    if nway_blocks:
        dispatch_region = frozenset(nway_blocks)
    else:
        dispatch_region = frozenset()

    case_blocks = frozenset(nodes - set(dispatch_region))

    compare_chain_length = sum(
        1 for i in range(qty)
        if (blk := target.get_mblock(i)) is not None
        and int(getattr(blk, "type", 0)) == _BLT_2WAY
    )
    dispatch_table_size = max(0, compare_chain_length)
    state_alias_count = 0
    has_default = False
    for serial in dispatch_region:
        succs = adj.get(serial, ())
        if len(succs) >= 2:
            has_default = True
            break

    return (
        dispatch_region,
        case_blocks,
        dispatch_table_size,
        compare_chain_length,
        state_alias_count,
        has_default,
        adj,
    )


class FlowProfileClassifierCollector:
    """Classify dispatch profile and persist strategy signals in Recon.

    Thin adapter: extracts structural components from the target, delegates
    to ``FlowProfileClassifier.from_components()``, and wraps the
    ``ClassificationResult`` into a ``ReconResult``.
    """

    name: str = "flow_profile_classifier"
    maturities: frozenset[int] = frozenset({_MMAT_CALLS, _MMAT_GLBOPT1})
    level: str = "microcode"

    def collect(self, target, func_ea: int, maturity: int) -> ReconResult:
        """Collect flow profile classification metrics.

        :param target: ``FlowGraph`` snapshot or live ``mba_t``.
        :param func_ea: Function effective address.
        :param maturity: Current maturity level.
        :return: Frozen ``ReconResult`` with classification metrics.
        """
        if hasattr(target, "blocks") and hasattr(target, "entry_serial"):
            components = _portable_components(target)
        else:
            components = _live_components(target)

        (
            dispatch_region,
            case_blocks,
            dispatch_table_size,
            compare_chain_length,
            state_alias_count,
            has_default,
            adj,
        ) = components

        result = FlowProfileClassifier.from_components(
            dispatch_region=dispatch_region,
            case_blocks=case_blocks,
            dispatch_table_size=dispatch_table_size,
            compare_chain_length=compare_chain_length,
            state_alias_count=state_alias_count,
            has_default=has_default,
            adj=adj,
        )

        metrics = MappingProxyType(
            {
                "pattern": result.pattern.value,
                "classification_confidence": float(result.confidence),
                "recommended_strategy": str(result.recommended_strategy),
                "reasoning": str(result.reasoning),
                "dispatch_table_size": int(dispatch_table_size),
                "compare_chain_length": int(compare_chain_length),
                "dispatch_region_size": len(dispatch_region),
                "case_block_count": len(case_blocks),
            }
        )

        candidates: list[CandidateFlag] = []
        if result.pattern.value != "unknown":
            anchor = min(dispatch_region) if dispatch_region else -1
            candidates.append(
                CandidateFlag(
                    kind=f"dispatch_pattern_{result.pattern.value}",
                    block_serial=int(anchor),
                    confidence=float(result.confidence),
                    detail=str(result.recommended_strategy),
                )
            )

        return ReconResult(
            collector_name=self.name,
            func_ea=int(func_ea),
            maturity=int(maturity),
            timestamp=time.time(),
            metrics=metrics,
            candidates=tuple(candidates),
        )
