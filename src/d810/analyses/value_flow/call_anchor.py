"""Call-anchor fact collector.

Records canonical call anchors and the local CFG context around them. Backend
opcode/rendering details remain evidence only; call behavior is authorized by
``Instruction.control.call_kind``.
"""
from __future__ import annotations

from d810.core.typing import Any
from d810.ir.maturity import EARLY_FACT_COLLECTION_IR_MATURITIES
from d810.ir.semantics import CallKind
from d810.ir.varnode import Space, Varnode
from d810.analyses.fact_collection_context import (
    FactCollectionContext,
    coerce_fact_collection_context,
    fact_provider_label,
)
from d810.analyses.value_flow.induction_carrier import (
    _InstructionView,
    _iter_instruction_views,
)
from d810.analyses.value_flow.terminal_byte_emitter import (
    _block_metadata,
)
from d810.analyses.value_flow.model import FactObservation

_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES


def _is_call(insn: _InstructionView) -> bool:
    return insn.call_kind is not None


def _call_kind(insn: _InstructionView) -> str:
    if insn.call_kind is CallKind.INDIRECT:
        return "indirect_call"
    if insn.call_kind is CallKind.INTRINSIC:
        return "intrinsic_call"
    return "direct_call"


def _call_target_signature(target: Varnode | None) -> str:
    if target is None:
        return "unknown-call-target"
    if target.space is Space.GLOBAL:
        return f"$0x{int(target.offset):x}"
    if target.space is Space.CONST:
        return f"#0x{int(target.offset):x}"
    return f"{target.space.value}{int(target.offset)}"


def _call_target(insn: _InstructionView) -> str:
    return _call_target_signature(insn.call_target)


def _copy_state(start_ea: int | None) -> str:
    if start_ea is None or start_ea < 0:
        return "synthetic_or_inserted"
    return "preserved_or_original"


def _ea_text(ea: int | None) -> str:
    return f"0x{int(ea):x}" if ea is not None else "unknown"


class CallAnchorFactCollector:
    """Observe call anchors and immediate CFG context across maturities."""

    name = "CallAnchorFactCollector"
    fact_kinds = frozenset({"CallAnchorFact"})
    maturities = _TARGET_MATURITIES

    def collect(
        self,
        target: Any,
        *,
        context: FactCollectionContext | None = None,
        func_ea: int | None = None,
        phase: str = "pre_d810",
        **legacy_fields: Any,
    ) -> tuple[FactObservation, ...]:
        context = coerce_fact_collection_context(
            context,
            func_ea=func_ea,
            phase=phase,
            legacy_fields=legacy_fields,
        )
        phase = context.phase
        maturity_text = fact_provider_label(context)
        metadata = _block_metadata(target)
        observations: list[FactObservation] = []
        seen: set[tuple[int, int, int]] = set()

        for insn in _iter_instruction_views(target):
            if not _is_call(insn):
                continue
            start_ea, succs, preds = metadata.get(insn.block_serial, (None, (), ()))
            dedupe = (insn.block_serial, insn.insn_index, int(insn.ea or 0))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            target_sig = _call_target(insn)
            call_kind = _call_kind(insn)
            semantic_key = (
                f"call_anchor:kind={call_kind}:target={target_sig}:"
                f"anchor=blk[{insn.block_serial}]:ea={_ea_text(insn.ea)}"
            )
            fact_id = (
                f"{semantic_key}:blk={insn.block_serial}:"
                f"insn={insn.insn_index}:ea=0x{int(insn.ea or 0):x}"
            )
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="CallAnchorFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.86,
                    source_block=insn.block_serial,
                    source_ea=insn.ea,
                    block_fingerprint=(
                        f"blk[{insn.block_serial}].{insn.insn_index}:{insn.opcode_name}"
                    ),
                    mop_signature=f"call:{call_kind}:{target_sig}",
                    payload={
                        "call_kind": call_kind,
                        "call_target": target_sig,
                        "opcode": insn.opcode_name,
                        "anchor_block": insn.block_serial,
                        "anchor_block_ea": start_ea,
                        "insn_index": insn.insn_index,
                        "successor_blocks": list(succs),
                        "predecessor_blocks": list(preds),
                        "copy_state": _copy_state(start_ea),
                        "has_outgoing_flow": bool(succs),
                        "has_incoming_flow": bool(preds),
                    },
                    evidence=(insn.dstr,),
                )
            )
        return tuple(observations)


__all__ = ["CallAnchorFactCollector"]
