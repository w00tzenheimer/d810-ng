"""Zero/blob initialization fact collector.

Captures zero-store and static-blob-copy shaped memory initializers so later
diffs can separate renderer artifacts from true initialization changes.

llr-3b41 S11 -- canonical-only.  A portable
:class:`~d810.ir.flowgraph.FlowGraph` block (the only shape a production fact
target ever is) is projected via ``InstructionProjection.from_block``; an
offline diag row carrying a parseable ``meta`` operand tree is lifted through
the SAME projection via :func:`d810.ir.insn_projection.project_diag_instruction`.
The classifier helpers read ``operation`` / ``memory`` / ``control`` off that
canonical record, so their facts are canonical-faithful (real
``ValueOpKind.STORE``, recovered call/memory operands).  There is no meta-less
fallback -- every production fact target is a canonical ``FlowGraph``.
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
    _call_args_from_instruction,
    _call_kind_from_instruction,
    _canonical_opcode_name,
    _value_op_from_instruction,
)
from d810.analyses.value_flow.model import FactObservation

_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES


@dataclass(frozen=True)
class _ZeroBlobInsn:
    """Uniform semantic view consumed by zero_blob's classifiers.

    Built solely from a canonical :class:`~d810.ir.instructions.Instruction`
    (llr-3b41 S11 deleted the legacy meta-less flat path).  Only the fields zero_blob actually reads are exposed; the classifier
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


def _iter_zero_blob_insns(target: Any) -> Iterable[_ZeroBlobInsn]:
    """Yield zero_blob's semantic record for every instruction in ``target``.

    Canonical-only (llr-3b41 S11): a meta-rich FlowGraph block is projected via
    ``InstructionProjection.from_block``; an offline diag row carrying a ``meta``
    operand tree is lifted via ``project_diag_instruction``.  The meta-less flat
    fallback was removed -- it was unreachable by any real source once every
    production fact target became a canonical ``FlowGraph``.  A registered live
    :class:`~d810.capabilities.source_lifter.SourceLifter` lifts a backend
    source to a portable flow graph first.
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
        for index, instruction in enumerate(InstructionProjection.from_block(blk)):
            yield _ZeroBlobInsn.from_canonical(
                block_serial=block_serial,
                index=index,
                instruction=instruction,
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
