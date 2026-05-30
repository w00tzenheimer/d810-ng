"""Zero/blob initialization fact collector.

Captures zero-store and static-blob-copy shaped memory initializers so later
diffs can separate renderer artifacts from true initialization changes.
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
    _memory_destination_signature,
)
from d810.analyses.value_flow.model import FactObservation

_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})

_ZERO_LITERAL_RE = re.compile(r"(?:^|[\s,(])#0(?:x0)?(?:\.\d+)?(?:[,\s)]|$)", re.IGNORECASE)
_BLOB_RE = re.compile(r"\b(?:unk_|off_|byte_|qword_|xmmword_)[0-9a-fA-F]+", re.IGNORECASE)
_COPY_SIZE_RE = re.compile(r"#(?P<size>0x[0-9a-fA-F]+|\d+)(?:\.\d+)?")


def _is_store(insn: _InstructionView) -> bool:
    text = insn.dstr.lower().lstrip()
    return insn.opcode_name in {"m_stx", "op_1", "store"} or text.startswith("stx ")


def _zero_blob_kind(insn: _InstructionView) -> str | None:
    text = insn.dstr
    lower = text.lower()
    if _is_store(insn) and _ZERO_LITERAL_RE.search(text):
        return "zero_store"
    if _is_store(insn) and _BLOB_RE.search(text):
        return "blob_store"
    if lower.startswith("call ") and ("memcpy" in lower or _BLOB_RE.search(text)):
        return "blob_copy_call"
    return None


def _copy_size(insn: _InstructionView) -> int | None:
    if insn.src_r_value is not None:
        return int(insn.src_r_value)
    matches = tuple(_COPY_SIZE_RE.finditer(insn.dstr))
    if not matches:
        return None
    try:
        return int(matches[-1].group("size"), 0)
    except ValueError:
        return None


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
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        maturity_text = _maturity_name(maturity)
        observations: list[FactObservation] = []
        seen: set[tuple[int, int, str]] = set()

        for insn in _iter_instruction_views(target):
            init_kind = _zero_blob_kind(insn)
            if init_kind is None:
                continue
            destination = _memory_destination_signature(insn)
            size = _copy_size(insn)
            semantic_key = (
                f"zero_blob_init:kind={init_kind}:dest={destination}:"
                f"size={size if size is not None else 'unknown'}:"
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
                    confidence=0.78 if init_kind == "zero_store" else 0.68,
                    source_block=insn.block_serial,
                    source_ea=insn.ea,
                    block_fingerprint=(
                        f"blk[{insn.block_serial}].{insn.insn_index}:{insn.opcode_name}"
                    ),
                    mop_signature=(
                        f"zero_blob:{init_kind}:dest={destination}:size={size}"
                    ),
                    payload={
                        "init_kind": init_kind,
                        "destination": destination,
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
