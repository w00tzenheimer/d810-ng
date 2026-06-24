"""Zero/blob initialization fact collector.

Captures zero-store and static-blob-copy shaped memory initializers so later
diffs can separate renderer artifacts from true initialization changes.

llr-3b41 S3 -- first per-collector port onto the canonical IR.  The reusable
pattern (documented here for S4-S9) is a dual-currency source iterator:

* **meta-rich** sources -- a portable :class:`~d810.ir.flowgraph.FlowGraph`
  block, or a diag row carrying a parseable ``meta`` operand tree -- are lifted
  to the canonical :class:`~d810.ir.instructions.Instruction` (the SAME
  projection :func:`d810.ir.insn_projection.project_instruction` /
  ``InstructionProjection.from_block`` produces).  The classifier helpers read
  ``operation`` / ``memory`` / ``control`` off that canonical record, so their
  facts become canonical-faithful (real ``ValueOpKind.STORE``, recovered
  call/memory operands) instead of opcode-table guesses.
* **meta-less** rows -- the production ``mba_to_fact_target``
  ``SimpleNamespace`` (flat fields only) and attrs-only ``meta`` rows
  (``{"byte_index": 1}``) -- have no operand tree, so they stay on the legacy
  ``_InstructionView`` flat-field path, BYTE-IDENTICAL.  ``diag_row_has_operand_tree``
  is the gate (mirrors the induction_carrier S2 split).  zero_blob only reads
  semantic fields (``memory_*`` / ``call_*`` / ``operation``) that the legacy
  flat path never populates, so meta-less rows already yield zero observations;
  the legacy path preserves that exactly.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from d810.capabilities.source_lifter import select_lifter
from d810.core.typing import Any, Iterable
from d810.ir.expressions import ValueOpKind
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
    _call_args_from_instruction,
    _call_kind_from_instruction,
    _canonical_opcode_name,
    _value_op_from_instruction,
    _value_op_from_opcode_name,
)
from d810.analyses.value_flow.model import FactObservation

_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES


@dataclass(frozen=True)
class _ZeroBlobInsn:
    """Uniform semantic view consumed by zero_blob's classifiers.

    Built from a canonical :class:`~d810.ir.instructions.Instruction` for a
    meta-rich source, or from a legacy :class:`_InstructionView` for a meta-less
    row.  Only the fields zero_blob actually reads are exposed; the classifier
    helpers below switch on ``operation`` / ``memory_*`` / ``call_*`` and never
    touch flat operand fields, so a meta-less row (whose canonical-shaped fields
    are all empty) classifies to ``None`` exactly as before.
    """

    block_serial: int
    insn_index: int
    ea: int | None
    opcode_name: str
    dstr: str
    operation: ValueOpKind | None
    memory_target: Varnode | None
    memory_value: Varnode | None
    call_kind: CallKind | None
    call_args: tuple[Varnode, ...]

    @classmethod
    def from_canonical(
        cls,
        *,
        block_serial: int,
        index: int,
        instruction: Instruction,
    ) -> "_ZeroBlobInsn":
        attrs = instruction.attrs
        ea_raw = attrs.get("ea")
        memory = instruction.memory
        return cls(
            block_serial=int(block_serial),
            insn_index=int(index),
            ea=int(ea_raw) if ea_raw is not None else None,
            opcode_name=_canonical_opcode_name(instruction),
            dstr=str(attrs.get("display_text") or ""),
            operation=_value_op_from_instruction(instruction),
            memory_target=memory.target if memory is not None else None,
            memory_value=memory.value if memory is not None else None,
            call_kind=_call_kind_from_instruction(instruction),
            call_args=_call_args_from_instruction(instruction),
        )

    @classmethod
    def from_legacy_view(cls, view: _InstructionView) -> "_ZeroBlobInsn":
        return cls(
            block_serial=view.block_serial,
            insn_index=view.insn_index,
            ea=view.ea,
            opcode_name=view.opcode_name,
            dstr=view.dstr,
            operation=view.operation,
            memory_target=view.memory_target,
            memory_value=view.memory_value,
            call_kind=view.call_kind,
            call_args=view.call_args,
        )


def _iter_zero_blob_insns(target: Any) -> Iterable[_ZeroBlobInsn]:
    """Yield zero_blob's semantic record for every instruction in ``target``.

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
                yield _ZeroBlobInsn.from_canonical(
                    block_serial=block_serial,
                    index=index,
                    instruction=instruction,
                )
            continue
        for index, insn in enumerate(getattr(blk, "instructions", ())):
            if diag_row_has_operand_tree(insn):
                yield _ZeroBlobInsn.from_canonical(
                    block_serial=block_serial,
                    index=int(getattr(insn, "index", index)),
                    instruction=project_diag_instruction(insn),
                )
                continue
            yield _ZeroBlobInsn.from_legacy_view(
                _legacy_view_from_diag_row(block_serial, index, insn)
            )


def _legacy_view_from_diag_row(
    block_serial: int, index: int, insn: Any
) -> _InstructionView:
    """Build the byte-identical legacy view for a meta-less diag row.

    zero_blob only reads the canonical-shaped semantic fields (``operation`` /
    ``memory_*`` / ``call_*``), none of which a meta-less flat row populates, so
    this view is intentionally minimal: it carries identity + the legacy
    opcode-name ``operation`` inference (matching the pre-S3
    ``_iter_portable_instructions`` flat path), leaving every memory/call field
    empty.  That makes a meta-less row classify to ``None`` -- exactly the
    pre-S3 behaviour.
    """
    opcode_name = str(getattr(insn, "opcode_name", ""))
    return _InstructionView(
        block_serial=block_serial,
        insn_index=int(getattr(insn, "index", index)),
        ea=getattr(insn, "ea", None),
        opcode_name=opcode_name,
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
        operation=_value_op_from_opcode_name(opcode_name),
    )


def _is_store(insn: _ZeroBlobInsn) -> bool:
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


def _static_blob_arg(insn: _ZeroBlobInsn) -> Varnode | None:
    for arg in insn.call_args:
        if arg.space is Space.GLOBAL:
            return arg
    return None


def _call_destination(insn: _ZeroBlobInsn) -> Varnode | None:
    for arg in insn.call_args:
        if arg.space not in {Space.CONST, Space.GLOBAL}:
            return arg
    return None


def _zero_blob_kind(insn: _ZeroBlobInsn) -> str | None:
    if _is_store(insn) and insn.memory_value is not None:
        if insn.memory_value.space is Space.CONST and int(insn.memory_value.offset) == 0:
            return "zero_store"
        if insn.memory_value.space is Space.GLOBAL:
            return "blob_store"
    if insn.call_kind is not None and _static_blob_arg(insn) is not None and _copy_size(insn):
        return "blob_copy_call"
    return None


def _destination_signature(insn: _ZeroBlobInsn) -> str:
    if _is_store(insn):
        return _varnode_signature(insn.memory_target)
    return _varnode_signature(_call_destination(insn))


def _copy_size(insn: _ZeroBlobInsn) -> int | None:
    for arg in reversed(insn.call_args):
        if arg.space is Space.CONST:
            return int(arg.offset)
    return None


def _source_signature(insn: _ZeroBlobInsn) -> str:
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

        for insn in _iter_zero_blob_insns(target):
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
