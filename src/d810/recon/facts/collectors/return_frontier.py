"""Return-frontier fact collector.

ReturnCarrierFact records individual return-slot writes.  This collector records
the local return frontier that consumes those carriers: terminal block, nearby
predecessor path, and carrier writers found on that path.
"""
from __future__ import annotations

from collections import deque

from d810.core.typing import Any
from d810.recon.facts.collectors.induction_carrier import (
    _MATURITY_VALUES,
    _maturity_name,
)
from d810.recon.facts.collectors.return_carrier import ReturnCarrierFactCollector
from d810.recon.facts.collectors.terminal_byte_emitter import (
    _BlockView,
    _block_metadata,
    _iter_block_views,
)
from d810.recon.facts.model import FactObservation

_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})

_RETURN_OPCODES = frozenset({"m_ret", "op_58"})


def _is_return_block(block: _BlockView) -> bool:
    if not block.succs:
        return True
    return any(
        insn.opcode_name in _RETURN_OPCODES or insn.dstr.lower().lstrip().startswith("ret")
        for insn in block.instructions
    )


def _predecessor_frontier(
    blocks: dict[int, _BlockView],
    ret_block: int,
    *,
    max_depth: int = 4,
) -> tuple[int, ...]:
    seen = {ret_block}
    ordered: list[int] = []
    queue: deque[tuple[int, int]] = deque((pred, 1) for pred in blocks[ret_block].preds)
    while queue:
        serial, depth = queue.popleft()
        if serial in seen or serial not in blocks:
            continue
        seen.add(serial)
        ordered.append(serial)
        if depth >= max_depth:
            continue
        for pred in blocks[serial].preds:
            queue.append((pred, depth + 1))
    return tuple(ordered)


def _carrier_digest(carriers: tuple[FactObservation, ...]) -> str:
    if not carriers:
        return "none"
    return "|".join(sorted({carrier.semantic_key for carrier in carriers}))


class ReturnFrontierFactCollector:
    """Observe return frontier paths and nearby return-carrier writers."""

    name = "ReturnFrontierFactCollector"
    fact_kinds = frozenset({"ReturnFrontierFact"})
    maturities = _TARGET_MATURITIES

    def __init__(self) -> None:
        self._carrier_collector = ReturnCarrierFactCollector()

    def collect(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        maturity_text = _maturity_name(maturity)
        metadata = _block_metadata(target)
        blocks = {block.serial: block for block in _iter_block_views(target)}
        for serial, (start_ea, succs, preds) in metadata.items():
            blocks.setdefault(
                serial,
                _BlockView(
                    serial=serial,
                    start_ea=start_ea,
                    succs=succs,
                    preds=preds,
                    instructions=(),
                ),
            )
        carriers = self._carrier_collector.collect(
            target,
            func_ea=func_ea,
            maturity=maturity,
            phase=phase,
        )
        carriers_by_block: dict[int, list[FactObservation]] = {}
        for carrier in carriers:
            if carrier.source_block is None:
                continue
            carriers_by_block.setdefault(int(carrier.source_block), []).append(carrier)

        observations: list[FactObservation] = []
        for block in sorted(blocks.values(), key=lambda item: item.serial):
            if not _is_return_block(block):
                continue
            frontier = _predecessor_frontier(blocks, block.serial)
            writer_blocks = tuple(
                serial for serial in frontier if serial in carriers_by_block
            )
            carrier_facts = tuple(
                carrier
                for serial in writer_blocks
                for carrier in carriers_by_block.get(serial, ())
            )
            start_ea, succs, preds = metadata.get(block.serial, (block.start_ea, (), ()))
            writer_text = ",".join(str(serial) for serial in writer_blocks) or "none"
            semantic_key = (
                f"return_frontier:return_block={block.serial}:"
                f"writers={writer_text}:carriers={_carrier_digest(carrier_facts)}"
            )
            fact_id = (
                f"{semantic_key}:frontier="
                f"{','.join(str(serial) for serial in frontier) or 'none'}"
            )
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="ReturnFrontierFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.72 if carrier_facts else 0.58,
                    source_block=block.serial,
                    source_ea=start_ea,
                    block_fingerprint=f"return_frontier:blk[{block.serial}]",
                    mop_signature=(
                        "return_frontier:"
                        + ",".join(carrier.mop_signature or "" for carrier in carrier_facts)
                    ),
                    payload={
                        "return_block": block.serial,
                        "return_block_ea": start_ea,
                        "predecessor_blocks": list(preds),
                        "successor_blocks": list(succs),
                        "frontier_blocks": list(frontier),
                        "writer_blocks": list(writer_blocks),
                        "carrier_fact_ids": [carrier.fact_id for carrier in carrier_facts],
                        "carrier_semantic_keys": [
                            carrier.semantic_key for carrier in carrier_facts
                        ],
                    },
                    evidence=tuple(
                        evidence
                        for carrier in carrier_facts
                        for evidence in carrier.evidence
                    ),
                )
            )
        return tuple(observations)


__all__ = ["ReturnFrontierFactCollector"]
