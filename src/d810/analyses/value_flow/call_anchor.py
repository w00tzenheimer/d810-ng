"""Call-anchor fact collector.

Records m_call/m_icall-shaped anchors and the local CFG context around them.
This is diagnostic-only substrate for later call-preservation work.
"""
from __future__ import annotations

import re

from d810.core.typing import Any
from d810.analyses.value_flow.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _iter_instruction_views,
    _maturity_name,
)
from d810.analyses.value_flow.terminal_byte_emitter import (
    _block_metadata,
)
from d810.analyses.value_flow.model import FactObservation

_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})

_CALL_OPCODES = frozenset({"m_call", "m_icall", "op_56", "op_57", "call"})
_CALL_TARGET_RE = re.compile(r"\bcall\s+([^<,\s]+)")


def _is_call(insn: _InstructionView) -> bool:
    text = insn.dstr.lower().lstrip()
    return insn.opcode_name in _CALL_OPCODES or text.startswith("call ")


def _call_kind(insn: _InstructionView) -> str:
    opcode = insn.opcode_name.lower()
    if opcode == "m_icall" or opcode == "op_57":
        return "indirect_call"
    target = _call_target(insn)
    if target in {"unknown-call-target", "indirect"}:
        return "indirect_call"
    return "direct_call"


def _call_target(insn: _InstructionView) -> str:
    match = _CALL_TARGET_RE.search(insn.dstr)
    if match is None:
        return "unknown-call-target"
    return match.group(1)


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
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        maturity_text = _maturity_name(maturity)
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
