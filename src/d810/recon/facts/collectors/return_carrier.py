"""Return-carrier fact collector.

This collector observes writes into the microcode return-slot carrier before
later optimizer passes can inline, fold, or sever the carrier identity.  It is
diagnostic only: it records facts for the maturity lifecycle and does not make
planner or CFG decisions.

When the return-slot write's source is a stkvar ``K`` (a one-step
``stack_identity_carrier``), the collector also performs a single-step backward
trace to locate the upstream instruction that defines ``K`` and records that
instruction's EA, block, opcode, full dstr, and the set of ``%var_NNN``
references it reads.  Later passes consult this payload at GLBOPT1+ to know
that a target block / stkvar set corresponds to a return-carrier MBA
materialization site even after IDA's CALLS phase has folded the canonical
``add ... -> %var_K; mov %var_K -> %var_8`` chain into a sub-instruction
operand tree.
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


# Match ``%var_NNN`` references in microcode dstr text.  The hex/decimal
# offset suffix is captured so the upstream MBA's stkvar reads can be
# enumerated without re-parsing the operand tree.
_VAR_REF_RE = re.compile(r"%var_([0-9A-Fa-f]+)")

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


def _find_upstream_writer(
    instructions: tuple[_InstructionView, ...],
    target_stkoff: int,
    *,
    exclude: _InstructionView | None = None,
) -> _InstructionView | None:
    """Return the LAST instruction PRECEDING ``exclude`` in iteration
    order that writes ``target_stkoff`` with ``mop_S`` dest, or
    ``None`` if no such writer exists or ``exclude`` is missing.

    Iteration order from :func:`_iter_instruction_views` walks blocks
    in serial-ascending order and instructions in ``insn_index`` order.
    For a carrier-mov at position P, only writers strictly preceding P
    are considered.  This avoids picking a function-wide LAST writer
    that has no def/use relationship with the carrier-mov: previously
    the function picked the last writer regardless of its position, so
    on functions with many writers to the same return-carrier slot the
    fact ended up pointing at an arbitrary later block instead of the
    actual canonical producer.

    Concrete observation: on ``sub_7FFD3338C040`` the canonical
    return-carrier MBA at block 140 EA ``0x180014333`` precedes the
    trampoline ``mov %var_7C8, %var_8`` at block 141 EA
    ``0x1800143c5``; the older "function-wide LAST" heuristic skipped
    block 140 because block 254 EA ``0x180015e84`` also writes
    ``%var_7C8`` (a different MBA with shorter ``var_refs``) later in
    iteration order.  Scoping by iteration position is sufficient to
    recover the canonical producer in both cases: when a carrier-mov
    ``mov %var_K, %var_8`` is reached, every reaching def of
    ``%var_K`` lies earlier in the function-wide iteration (because
    ``_iter_instruction_views`` walks blocks in topological order for
    the captured snapshot).  Multi-step chains and CFG-aware
    reaching-def analysis remain follow-up work.
    """
    if exclude is None:
        return None
    anchor_block = int(exclude.block_serial)
    anchor_index = int(exclude.insn_index)
    last: _InstructionView | None = None
    for insn in instructions:
        ins_block = int(insn.block_serial)
        ins_idx = int(insn.insn_index)
        # Stop at or past the carrier-mov: writers at the same block
        # AFTER the carrier-mov cannot be its reaching def, and writers
        # in higher-numbered blocks come after the carrier-mov in the
        # function-wide iteration order.
        if ins_block > anchor_block:
            break
        if ins_block == anchor_block and ins_idx >= anchor_index:
            break
        if insn.dest_stkoff is None or insn.dest_type != "mop_S":
            continue
        if int(insn.dest_stkoff) != int(target_stkoff):
            continue
        last = insn
    return last


def _extract_var_refs(dstr: str) -> tuple[str, ...]:
    """Return the set of ``%var_NNN`` token suffixes referenced in
    ``dstr``, in stable lexical order.  Used to expose the upstream
    MBA's stkvar reads in the fact payload without parsing the operand
    tree.  Names (not numeric stkoffs) because the dstr does not
    record the raw mop_S offsets for nested operands.
    """
    seen: set[str] = set()
    for match in _VAR_REF_RE.finditer(dstr):
        seen.add(match.group(1).lower())
    return tuple(sorted(seen))


def _carrier_class(insn: _InstructionView) -> str:
    opcode = insn.opcode_name.lower()
    text = insn.dstr.lower()
    if "xdu" in opcode or text.lstrip().startswith("xdu"):
        return "protected_non_carrier_return_writer_candidate"
    if opcode in {"m_mov", "op_4"} and insn.src_l_stkoff is not None:
        return "stack_identity_carrier"
    if insn.src_l_value is not None or insn.src_r_value is not None:
        return "constant_or_offset_return"
    return "computed_return"


class ReturnSlotFactCollector:
    """Observe return-slot writes across maturities.

    Canonical class name (value-flow rename Phase 4). Tracks the storage
    slot used to communicate a function's return value at the ABI
    boundary (e.g. ``%var_8.8`` for stack-returned aggregates). A peer
    class :class:`ReturnValueFactCollector` is reserved for facts about
    the recovered semantic value once a producer exists.

    The legacy class name ``ReturnCarrierFactCollector`` is preserved as
    an alias at the end of this module. The serialized
    ``FactObservation.kind`` value stays ``"ReturnCarrierFact"`` so old
    diag SQLite snapshots remain queryable via the Phase 3 alias
    registry.
    """

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
            payload: dict[str, Any] = {
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
            }

            # When the carrier is a stack identity (the canonical
            # OLLVM ``mov %var_K -> %var_8`` trampoline), record the
            # upstream instruction that defines ``%var_K``.  This
            # captures the return-carrier MBA's identity *before* IDA's
            # CALLS phase folds the chain into a sub-instruction
            # operand tree, so later GLBOPT1 consumers can recognise
            # the materialization site even when its canonical form
            # has been erased.
            evidence: tuple[str, ...] = (insn.dstr,)
            if (
                carrier_class == "stack_identity_carrier"
                and insn.src_l_stkoff is not None
            ):
                upstream = _find_upstream_writer(
                    instructions,
                    int(insn.src_l_stkoff),
                    exclude=insn,
                )
                if upstream is not None:
                    upstream_var_refs = _extract_var_refs(upstream.dstr)
                    payload.update({
                        "carrier_dst_stkoff": int(insn.src_l_stkoff),
                        "upstream_writer_block_serial": upstream.block_serial,
                        "upstream_writer_insn_index": upstream.insn_index,
                        "upstream_writer_ea": upstream.ea,
                        "upstream_writer_opcode": upstream.opcode_name,
                        "upstream_writer_dest_stkoff": upstream.dest_stkoff,
                        "upstream_writer_dstr": upstream.dstr,
                        "upstream_writer_var_refs": list(upstream_var_refs),
                    })
                    evidence = (insn.dstr, upstream.dstr)

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
                    payload=payload,
                    evidence=evidence,
                )
            )
        return tuple(observations)


__all__ = ["ReturnCarrierFactCollector"]


class ReturnValueFactCollector:
    """Placeholder collector for facts about the recovered return value.

    Distinct from :class:`ReturnSlotFactCollector`, which records facts
    about the storage slot. The split was decided in answer to open
    question 3 of the value-flow rename design. No producer is wired up
    yet; consumers can already target the canonical split shape so that
    a future producer landing here does not require a second migration.
    """

    name = "ReturnValueFactCollector"
    fact_kinds = frozenset({"ReturnValueFact"})
    maturities = _TARGET_MATURITIES

    def collect(
        self,
        target: object,
        *,
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        return ()


# Legacy class name kept as an alias during the value-flow rename. The
# current slot-based collector logic lives in ReturnSlotFactCollector;
# ReturnValueFactCollector is the future home for value-recovery facts.
ReturnCarrierFactCollector = ReturnSlotFactCollector
