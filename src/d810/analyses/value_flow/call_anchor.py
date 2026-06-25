"""Call-anchor fact collector.

Records canonical call anchors and the local CFG context around them. Backend
opcode/rendering details remain evidence only; call behavior is authorized by
``Instruction.control.call_kind``.

llr-3b41 S4 -- per-collector port onto the canonical IR, following the proven S3
(:mod:`d810.analyses.value_flow.zero_blob`) pattern.  A collector-local
dual-currency iterator routes:

* **meta-rich** sources -- a portable :class:`~d810.ir.flowgraph.FlowGraph`
  block, or a diag row carrying a parseable ``meta`` operand tree -- through the
  SAME canonical :func:`~d810.ir.insn_projection.project_diag_instruction` /
  ``InstructionProjection.from_block`` projection.  The classifiers then read
  ``control.call_kind`` / ``control.call_target`` off the canonical record, so a
  call anchor is authorized by recovered call semantics, not an opcode guess.
* **meta-less** rows -- the production ``mba_to_fact_target``
  ``SimpleNamespace`` (flat fields only) and attrs-only ``meta`` rows -- have no
  operand tree, so they stay on the legacy ``_InstructionView`` flat path,
  BYTE-IDENTICAL.  ``diag_row_has_operand_tree`` is the gate (mirrors S3).
  call_anchor only reads call-shaped fields (``call_kind`` / ``call_target``)
  that the legacy flat path never populates, so a meta-less row yields zero
  observations exactly as before.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from d810.capabilities.source_lifter import select_lifter
from d810.core.typing import Any, Iterable
from d810.ir.instructions import Instruction
from d810.ir.insn_projection import (
    InstructionProjection,
    diag_row_has_operand_tree,
    project_diag_instruction,
)
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
    _call_kind_from_instruction,
    _call_target_from_instruction,
    _canonical_opcode_name,
)
from d810.analyses.value_flow.terminal_byte_emitter import (
    _block_metadata,
)
from d810.analyses.value_flow.model import FactObservation

_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES


@dataclass(frozen=True)
class _CallAnchorInsn:
    """Uniform semantic view consumed by call_anchor's classifiers.

    Built from a canonical :class:`~d810.ir.instructions.Instruction` for a
    meta-rich source, or from a legacy :class:`_InstructionView` for a meta-less
    row.  Only the fields call_anchor actually reads are exposed; the classifier
    helpers below switch on ``call_kind`` / ``call_target`` and never touch flat
    operand fields, so a meta-less row (whose canonical-shaped call fields are
    all empty) classifies to "not a call" exactly as before.
    """

    block_serial: int
    insn_index: int
    ea: int | None
    opcode_name: str
    dstr: str
    call_kind: CallKind | None
    call_target: Varnode | None

    @classmethod
    def from_canonical(
        cls,
        *,
        block_serial: int,
        index: int,
        instruction: Instruction,
    ) -> "_CallAnchorInsn":
        attrs = instruction.attrs
        ea_raw = attrs.get("ea")
        return cls(
            block_serial=int(block_serial),
            insn_index=int(index),
            ea=int(ea_raw) if ea_raw is not None else None,
            opcode_name=_canonical_opcode_name(instruction),
            dstr=str(attrs.get("display_text") or ""),
            call_kind=_call_kind_from_instruction(instruction),
            call_target=_call_target_from_instruction(instruction),
        )

    @classmethod
    def from_legacy_view(cls, view: _InstructionView) -> "_CallAnchorInsn":
        return cls(
            block_serial=view.block_serial,
            insn_index=view.insn_index,
            ea=view.ea,
            opcode_name=view.opcode_name,
            dstr=view.dstr,
            call_kind=view.call_kind,
            call_target=view.call_target,
        )


def _iter_call_anchor_insns(target: Any) -> Iterable[_CallAnchorInsn]:
    """Yield call_anchor's semantic record for every instruction in ``target``.

    Dual-currency (see module docstring): meta-rich FlowGraph blocks and
    operand-tree diag rows are lifted to canonical ``Instruction``; meta-less
    rows stay on the byte-identical legacy ``_InstructionView`` flat path.  A
    registered live :class:`~d810.capabilities.source_lifter.SourceLifter`
    lifts a backend source to a portable flow graph first (behaviour-identical
    to no-lifter when none is registered).
    """
    lifter = select_lifter(target)
    if lifter is not None:
        target = lifter.lift(target)

    blocks = getattr(target, "blocks", target)
    if isinstance(blocks, Mapping):
        block_iter = blocks.values()
    else:
        block_iter = blocks

    for blk in block_iter:
        block_serial = int(getattr(blk, "serial"))
        if getattr(blk, "insn_snapshots", None) is not None:
            for index, instruction in enumerate(InstructionProjection.from_block(blk)):
                yield _CallAnchorInsn.from_canonical(
                    block_serial=block_serial,
                    index=index,
                    instruction=instruction,
                )
            continue
        for index, insn in enumerate(getattr(blk, "instructions", ())):
            if diag_row_has_operand_tree(insn):
                yield _CallAnchorInsn.from_canonical(
                    block_serial=block_serial,
                    index=int(getattr(insn, "index", index)),
                    instruction=project_diag_instruction(insn),
                )
                continue
            yield _CallAnchorInsn.from_legacy_view(
                _legacy_view_from_diag_row(block_serial, index, insn)
            )


def _legacy_view_from_diag_row(
    block_serial: int, index: int, insn: Any
) -> _InstructionView:
    """Build the byte-identical legacy view for a meta-less diag row.

    call_anchor only reads the canonical-shaped call fields (``call_kind`` /
    ``call_target``), neither of which a meta-less flat row populates, so this
    view is intentionally minimal: it carries identity only, leaving the call
    fields empty.  That makes a meta-less row classify to "not a call" -- exactly
    the pre-S4 behaviour.
    """
    return _InstructionView(
        block_serial=block_serial,
        insn_index=int(getattr(insn, "index", index)),
        ea=getattr(insn, "ea", None),
        opcode_name=str(getattr(insn, "opcode_name", "")),
        dest_type=getattr(insn, "dest_type", None),
        dest_stkoff=None,
        dest_size=getattr(insn, "dest_size", None),
        src_l_type=getattr(insn, "src_l_type", None),
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type=getattr(insn, "src_r_type", None),
        src_r_stkoff=None,
        src_r_value=None,
        dstr=str(getattr(insn, "dstr", "")),
    )


def _is_call(insn: _CallAnchorInsn) -> bool:
    return insn.call_kind is not None


def _call_kind(insn: _CallAnchorInsn) -> str:
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


def _call_target(insn: _CallAnchorInsn) -> str:
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

        for insn in _iter_call_anchor_insns(target):
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
