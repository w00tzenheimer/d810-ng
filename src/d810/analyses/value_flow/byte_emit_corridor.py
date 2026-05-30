"""Byte-emitter corridor fact collector.

This collector summarizes per-byte terminal-emitter observations into a single
family-level structural fact.  It is observability-only: consumers can query
which byte families survive or remap without treating individual byte steps as
the whole corridor.
"""
from __future__ import annotations

from d810.core.typing import Any
from d810.analyses.value_flow.induction_carrier import (
    _MATURITY_VALUES,
    _maturity_name,
)
from d810.analyses.value_flow.terminal_byte_emitter import (
    TerminalByteEmitterFactCollector,
)
from d810.analyses.value_flow.model import FactObservation

_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})


def _step_sort_key(observation: FactObservation) -> tuple[int, int, int]:
    byte_index = int(observation.payload.get("byte_index", -1))
    block = int(observation.source_block or -1)
    insn = int(observation.payload.get("insn_index", -1))
    return (byte_index, block, insn)


class ByteEmitCorridorFactCollector:
    """Observe byte-emitter corridors by grouping per-byte emitter facts."""

    name = "ByteEmitCorridorFactCollector"
    fact_kinds = frozenset({"ByteEmitCorridorFact"})
    maturities = _TARGET_MATURITIES

    def __init__(self) -> None:
        self._byte_collector = TerminalByteEmitterFactCollector()

    def collect(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        maturity_text = _maturity_name(maturity)
        byte_facts = self._byte_collector.collect(
            target,
            func_ea=func_ea,
            maturity=maturity,
            phase=phase,
        )
        by_family: dict[str, list[FactObservation]] = {}
        for observation in byte_facts:
            family = str(observation.payload.get("family_id") or "unknown_family")
            by_family.setdefault(family, []).append(observation)

        observations: list[FactObservation] = []
        for family, members in sorted(by_family.items()):
            ordered = tuple(sorted(members, key=_step_sort_key))
            if len(ordered) < 2:
                continue
            byte_indexes = tuple(
                int(member.payload.get("byte_index", -1))
                for member in ordered
            )
            source_blocks = tuple(
                int(member.source_block)
                for member in ordered
                if member.source_block is not None
            )
            source_eas = tuple(
                int(member.source_ea)
                for member in ordered
                if member.source_ea is not None
            )
            unique_bytes = tuple(sorted(set(byte_indexes)))
            unique_destinations = tuple(sorted({
                str(member.payload.get("destination_buffer_expression"))
                for member in ordered
            }))
            unique_counters = tuple(sorted({
                str(member.payload.get("counter_carrier"))
                for member in ordered
            }))
            byte_text = ",".join(str(byte) for byte in unique_bytes)
            first_block = source_blocks[0] if source_blocks else None
            first_ea = source_eas[0] if source_eas else None
            semantic_key = f"byte_emit_corridor:family={family}:bytes={byte_text}"
            fact_id = (
                f"{semantic_key}:blocks="
                f"{','.join(str(block) for block in source_blocks)}"
            )
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="ByteEmitCorridorFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=min(member.confidence for member in ordered),
                    source_block=first_block,
                    source_ea=first_ea,
                    block_fingerprint=(
                        "byte_emit_corridor:"
                        + ",".join(f"blk[{block}]" for block in source_blocks)
                    ),
                    mop_signature=(
                        f"byte_emit_corridor:family={family}:bytes={byte_text}"
                    ),
                    payload={
                        "family_id": family,
                        "byte_indexes": list(byte_indexes),
                        "unique_byte_indexes": list(unique_bytes),
                        "source_blocks": list(source_blocks),
                        "source_eas": [f"0x{ea:x}" for ea in source_eas],
                        "destinations": list(unique_destinations),
                        "counters": list(unique_counters),
                        "member_fact_ids": [member.fact_id for member in ordered],
                        "member_count": len(ordered),
                    },
                    evidence=tuple(
                        evidence
                        for member in ordered
                        for evidence in member.evidence[:1]
                    ),
                )
            )
        return tuple(observations)


__all__ = ["ByteEmitCorridorFactCollector"]
