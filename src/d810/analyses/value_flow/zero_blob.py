"""Zero/blob initialization fact collector.

Captures zero-store and static-blob-copy shaped memory initializers so later
diffs can separate renderer artifacts from true initialization changes.
"""
from __future__ import annotations

from d810.core.typing import Any
from d810.ir.expressions import ValueOpKind
from d810.ir.maturity import EARLY_FACT_COLLECTION_IR_MATURITIES
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
from d810.analyses.value_flow.model import FactObservation

_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES


def _is_store(insn: _InstructionView) -> bool:
    return insn.operation is ValueOpKind.STORE


def _varnode_signature(vn: Varnode | None) -> str:
    if vn is None:
        return "unknown"
    if vn.space is Space.GLOBAL:
        return f"$0x{int(vn.offset):x}"
    if vn.space is Space.CONST:
        return f"#0x{int(vn.offset):x}"
    if vn.space is Space.STACK:
        return f"mop_S:0x{int(vn.offset):x}"
    if vn.space is Space.REGISTER:
        return f"mop_r:{int(vn.offset)}"
    if vn.space is Space.LVAR:
        return f"mop_l:0x{int(vn.offset):x}"
    return f"{vn.space.value}{int(vn.offset)}"


def _static_blob_arg(insn: _InstructionView) -> Varnode | None:
    for arg in insn.call_args:
        if arg.space is Space.GLOBAL:
            return arg
    return None


def _call_destination(insn: _InstructionView) -> Varnode | None:
    for arg in insn.call_args:
        if arg.space not in {Space.CONST, Space.GLOBAL}:
            return arg
    return None


def _zero_blob_kind(insn: _InstructionView) -> str | None:
    if _is_store(insn) and insn.memory_value is not None:
        if insn.memory_value.space is Space.CONST and int(insn.memory_value.offset) == 0:
            return "zero_store"
        if insn.memory_value.space is Space.GLOBAL:
            return "blob_store"
    if insn.call_kind is not None and _static_blob_arg(insn) is not None and _copy_size(insn):
        return "blob_copy_call"
    return None


def _destination_signature(insn: _InstructionView) -> str:
    if _is_store(insn):
        return _varnode_signature(insn.memory_target)
    return _varnode_signature(_call_destination(insn))


def _copy_size(insn: _InstructionView) -> int | None:
    for arg in reversed(insn.call_args):
        if arg.space is Space.CONST:
            return int(arg.offset)
    return None


def _source_signature(insn: _InstructionView) -> str:
    if _is_store(insn):
        return _varnode_signature(insn.memory_value)
    blob_arg = _static_blob_arg(insn)
    if blob_arg is not None:
        return _varnode_signature(blob_arg)
    return "unknown"


def _confidence(init_kind: str) -> float:
    if init_kind == "zero_store":
        return 0.78
    if init_kind == "blob_store":
        return 0.72
    return 0.68


def _ea_text(ea: int | None) -> str:
    return f"0x{int(ea):x}" if ea is not None else "unknown"


class ZeroBlobFactCollector:
    """Observe zero-store and blob-copy initialization shapes."""

    name = "ZeroBlobFactCollector"
    fact_kinds = frozenset({"ZeroBlobFact"})
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
        observations: list[FactObservation] = []
        seen: set[tuple[int, int, str]] = set()

        for insn in _iter_instruction_views(target):
            init_kind = _zero_blob_kind(insn)
            if init_kind is None:
                continue
            destination = _destination_signature(insn)
            source = _source_signature(insn)
            size = _copy_size(insn)
            semantic_key = (
                f"zero_blob_init:kind={init_kind}:dest={destination}:"
                f"source={source}:size={size if size is not None else 'unknown'}:"
                f"ea={_ea_text(insn.ea)}"
            )
            dedupe = (insn.block_serial, insn.insn_index, semantic_key)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            fact_id = (
                f"{semantic_key}:blk={insn.block_serial}:"
                f"insn={insn.insn_index}:ea=0x{int(insn.ea or 0):x}"
            )
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="ZeroBlobFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=_confidence(init_kind),
                    source_block=insn.block_serial,
                    source_ea=insn.ea,
                    block_fingerprint=(
                        f"blk[{insn.block_serial}].{insn.insn_index}:{insn.opcode_name}"
                    ),
                    mop_signature=(
                        f"zero_blob:{init_kind}:dest={destination}:source={source}:size={size}"
                    ),
                    payload={
                        "init_kind": init_kind,
                        "destination": destination,
                        "source": source,
                        "size": size,
                        "opcode": insn.opcode_name,
                        "block_serial": insn.block_serial,
                        "insn_index": insn.insn_index,
                        "source_ea": _ea_text(insn.ea),
                    },
                    evidence=(insn.dstr,),
                )
            )
        return tuple(observations)


__all__ = ["ZeroBlobFactCollector"]
