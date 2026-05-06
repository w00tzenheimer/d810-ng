"""Return-carrier fact collector.

This collector observes writes into the microcode return-slot carrier before
later optimizer passes can inline, fold, or sever the carrier identity.  It is
diagnostic only: it records facts for the maturity lifecycle and does not make
planner or CFG decisions.
"""
from __future__ import annotations

import re

from d810.core.typing import Any
from d810.recon.facts.collectors.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _iter_instruction_views,
    _maturity_name,
)
from d810.recon.facts.model import FactObservation

_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})

_RETURN_SLOT_TO_RAX_RE = re.compile(
    r"\bmov\s+%var_8\.\d+\s*,\s*rax\.\d+",
    re.IGNORECASE,
)


def _is_return_register_read(insn: _InstructionView) -> bool:
    if insn.src_l_stkoff is None:
        return False
    if insn.dest_type != "mop_r":
        return False
    return bool(_RETURN_SLOT_TO_RAX_RE.search(insn.dstr))


def _return_slot_offsets(instructions: tuple[_InstructionView, ...]) -> frozenset[int]:
    return frozenset(
        int(insn.src_l_stkoff)
        for insn in instructions
        if _is_return_register_read(insn)
    )


def _source_signature(insn: _InstructionView) -> str:
    if insn.src_l_stkoff is not None:
        return f"{insn.src_l_type or 'src_l'}:0x{int(insn.src_l_stkoff):x}"
    if insn.src_l_value is not None:
        return f"const:0x{int(insn.src_l_value):x}"
    if insn.src_r_stkoff is not None:
        return f"{insn.src_r_type or 'src_r'}:0x{int(insn.src_r_stkoff):x}"
    if insn.src_r_value is not None:
        return f"const:0x{int(insn.src_r_value):x}"
    return "computed"


def _carrier_class(insn: _InstructionView) -> str:
    opcode = insn.opcode_name.lower()
    text = insn.dstr.lower()
    if "xdu" in opcode or text.lstrip().startswith("xdu"):
        return "state_guard_artifact_candidate"
    if opcode in {"m_mov", "op_4"} and insn.src_l_stkoff is not None:
        return "stack_identity_carrier"
    if insn.src_l_value is not None or insn.src_r_value is not None:
        return "constant_or_offset_return"
    return "computed_return"


class ReturnCarrierFactCollector:
    """Observe return-slot carrier writes across maturities."""

    name = "ReturnCarrierFactCollector"
    fact_kinds = frozenset({"ReturnCarrierFact"})
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
        instructions = tuple(_iter_instruction_views(target))
        return_slots = _return_slot_offsets(instructions)
        if not return_slots:
            return ()

        observations: list[FactObservation] = []
        seen: set[tuple[int, int, int]] = set()
        for insn in instructions:
            if insn.dest_stkoff is None or int(insn.dest_stkoff) not in return_slots:
                continue
            if insn.dest_type != "mop_S":
                continue
            dest_size = int(insn.dest_size or 0)
            dedupe = (insn.block_serial, insn.insn_index, int(insn.dest_stkoff))
            if dedupe in seen:
                continue
            seen.add(dedupe)

            slot = int(insn.dest_stkoff)
            source = _source_signature(insn)
            carrier_class = _carrier_class(insn)
            semantic_key = (
                f"return_carrier:slot=0x{slot:x}:class={carrier_class}:"
                f"source={source}"
            )
            fact_id = (
                f"{semantic_key}:blk={insn.block_serial}:"
                f"insn={insn.insn_index}:ea=0x{int(insn.ea or 0):x}"
            )
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="ReturnCarrierFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.86,
                    source_block=insn.block_serial,
                    source_ea=insn.ea,
                    block_fingerprint=(
                        f"blk[{insn.block_serial}].{insn.insn_index}:"
                        f"{insn.opcode_name}"
                    ),
                    mop_signature=f"return_slot:mop_S:0x{slot:x}:{dest_size}",
                    payload={
                        "return_slot_stkoff": slot,
                        "dest_size": dest_size,
                        "opcode": insn.opcode_name,
                        "carrier_class": carrier_class,
                        "source_signature": source,
                        "source_l_type": insn.src_l_type,
                        "source_l_stkoff": insn.src_l_stkoff,
                        "source_l_value": insn.src_l_value,
                        "source_r_type": insn.src_r_type,
                        "source_r_stkoff": insn.src_r_stkoff,
                        "source_r_value": insn.src_r_value,
                        "block_serial": insn.block_serial,
                        "insn_index": insn.insn_index,
                    },
                    evidence=(insn.dstr,),
                )
            )
        return tuple(observations)


__all__ = ["ReturnCarrierFactCollector"]
