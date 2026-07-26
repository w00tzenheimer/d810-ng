from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.analyses.value_flow.model import FactConsumerRecord


def _runtime_identity(value: object) -> int:
    try:
        return int(value.this)  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        return id(value)


@dataclass(frozen=True)
class LiveNopSite:
    """One callback-local NOP site with an EA-anchored block identity."""

    block_runtime_identity: int
    instruction_runtime_identity: int
    block_serial: int
    block_start_ea: int
    block_end_ea: int
    instruction_ea: int
    instruction_ordinal: int

    @property
    def runtime_key(self) -> tuple[int, int]:
        return self.block_runtime_identity, self.instruction_runtime_identity

    @property
    def block_anchor(self) -> str:
        return f"blk{self.block_serial}@0x{self.block_start_ea:x}"


def capture_live_nop_sites(mba: object) -> tuple[LiveNopSite, ...]:
    """Capture callback-local NOP sites without retaining live SDK objects."""
    sites: list[LiveNopSite] = []
    block_count = int(getattr(mba, "qty", 0) or 0)
    get_mblock = getattr(mba, "get_mblock", None)
    if block_count <= 0 or not callable(get_mblock):
        return ()

    for serial in range(block_count):
        block = get_mblock(serial)
        if block is None:
            continue
        instruction = getattr(block, "head", None)
        ordinal = 0
        seen_instructions: set[int] = set()
        while instruction is not None:
            instruction_runtime_identity = _runtime_identity(instruction)
            if instruction_runtime_identity in seen_instructions:
                break
            seen_instructions.add(instruction_runtime_identity)
            if int(getattr(instruction, "opcode", -1)) == int(ida_hexrays.m_nop):
                sites.append(
                    LiveNopSite(
                        block_runtime_identity=_runtime_identity(block),
                        instruction_runtime_identity=instruction_runtime_identity,
                        block_serial=int(getattr(block, "serial", serial)),
                        block_start_ea=int(getattr(block, "start", 0) or 0),
                        block_end_ea=int(getattr(block, "end", 0) or 0),
                        instruction_ea=int(getattr(instruction, "ea", 0) or 0),
                        instruction_ordinal=ordinal,
                    )
                )
            instruction = getattr(instruction, "next", None)
            ordinal += 1
    return tuple(sites)


def build_callback_nop_delta_records(
    *,
    before: tuple[LiveNopSite, ...],
    after: tuple[LiveNopSite, ...],
    callback_kind: str,
    callback_name: str,
    callback_result: int | None,
    maturity: str,
    exception_name: str | None = None,
) -> tuple[FactConsumerRecord, ...]:
    """Describe NOPs created by one callback and whether it reported a write."""
    before_keys = {site.runtime_key for site in before}
    created = tuple(site for site in after if site.runtime_key not in before_keys)
    if not created:
        return ()

    if exception_name is not None:
        decision = "mutation_result_missing"
        reason = "callback raised after creating an m_nop"
    elif callback_result == 0:
        decision = "mutation_unreported"
        reason = "callback returned zero after creating an m_nop"
    else:
        decision = "mutation_reported"
        reason = "callback returned a nonzero mutation result"

    records: list[FactConsumerRecord] = []
    for site in created:
        payload: dict[str, object] = {
            "block_anchor": site.block_anchor,
            "block_end_ea": f"0x{site.block_end_ea:x}",
            "callback_kind": str(callback_kind),
            "callback_name": str(callback_name),
            "callback_result": callback_result,
            "instruction_ea": f"0x{site.instruction_ea:x}",
            "instruction_ordinal": int(site.instruction_ordinal),
        }
        if exception_name is not None:
            payload["exception_name"] = str(exception_name)
        records.append(
            FactConsumerRecord(
                consumer="hexrays_callback",
                strategy="hexrays_callback_nop_delta",
                fact_id=(
                    f"callback-nop:{callback_kind}:{callback_name}:"
                    f"0x{site.block_start_ea:x}:0x{site.instruction_ea:x}:"
                    f"{site.instruction_ordinal}"
                ),
                maturity=str(maturity),
                decision=decision,
                reason=reason,
                payload=payload,
            )
        )
    return tuple(records)


__all__ = [
    "LiveNopSite",
    "build_callback_nop_delta_records",
    "capture_live_nop_sites",
]
