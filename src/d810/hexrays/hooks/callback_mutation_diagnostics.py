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
    instruction_path: str

    @property
    def runtime_key(self) -> tuple[int, int]:
        return self.block_runtime_identity, self.instruction_runtime_identity

    @property
    def block_anchor(self) -> str:
        return f"blk{self.block_serial}@0x{self.block_start_ea:x}"


def _iter_operand_subinstructions(
    operand: object,
    *,
    path: str,
    seen_instructions: set[int],
):
    operand_type = int(getattr(operand, "t", -1))
    if operand_type == int(ida_hexrays.mop_d):
        nested = getattr(operand, "d", None)
        if nested is not None:
            yield from _iter_instruction_tree(
                nested,
                path=f"{path}.d",
                seen_instructions=seen_instructions,
            )
        return
    if operand_type == int(ida_hexrays.mop_a):
        address = getattr(operand, "a", None)
        nested_operand = getattr(address, "v", address)
        if nested_operand is not None:
            yield from _iter_operand_subinstructions(
                nested_operand,
                path=f"{path}.a",
                seen_instructions=seen_instructions,
            )
        return
    if operand_type == int(ida_hexrays.mop_f):
        call_info = getattr(operand, "f", None)
        arguments = getattr(call_info, "args", ()) if call_info is not None else ()
        for index, argument in enumerate(arguments):
            yield from _iter_operand_subinstructions(
                argument,
                path=f"{path}.arg[{index}]",
                seen_instructions=seen_instructions,
            )
        return
    if operand_type == int(ida_hexrays.mop_p):
        pair = getattr(operand, "pair", None)
        if pair is None:
            return
        for name in ("lop", "hop"):
            pair_operand = getattr(pair, name, None)
            if pair_operand is not None:
                yield from _iter_operand_subinstructions(
                    pair_operand,
                    path=f"{path}.{name}",
                    seen_instructions=seen_instructions,
                )


def _iter_instruction_tree(
    instruction: object,
    *,
    path: str,
    seen_instructions: set[int],
):
    instruction_identity = _runtime_identity(instruction)
    if instruction_identity in seen_instructions:
        return
    seen_instructions.add(instruction_identity)
    yield path, instruction
    for slot_name in ("l", "r", "d"):
        operand = getattr(instruction, slot_name, None)
        if operand is not None:
            yield from _iter_operand_subinstructions(
                operand,
                path=f"{path}.{slot_name}",
                seen_instructions=seen_instructions,
            )


def capture_live_nop_sites(mba: object) -> tuple[LiveNopSite, ...]:
    """Capture top-level and nested NOPs without retaining live SDK objects."""
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
            if _runtime_identity(instruction) in seen_instructions:
                break
            for instruction_path, candidate in _iter_instruction_tree(
                instruction,
                path=f"top[{ordinal}]",
                seen_instructions=seen_instructions,
            ):
                if int(getattr(candidate, "opcode", -1)) == int(ida_hexrays.m_nop):
                    sites.append(
                        LiveNopSite(
                            block_runtime_identity=_runtime_identity(block),
                            instruction_runtime_identity=_runtime_identity(candidate),
                            block_serial=int(getattr(block, "serial", serial)),
                            block_start_ea=int(getattr(block, "start", 0) or 0),
                            block_end_ea=int(getattr(block, "end", 0) or 0),
                            instruction_ea=int(getattr(candidate, "ea", 0) or 0),
                            instruction_ordinal=ordinal,
                            instruction_path=instruction_path,
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
            "instruction_path": site.instruction_path,
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
                    f"{site.instruction_path}"
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
