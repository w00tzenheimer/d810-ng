"""Induction-carrier fact collector.

The first vertical collector is deliberately conservative: it records direct
stack-variable self updates, such as ``x = x + 0x80`` or ``x = x - 1``.  More
complex recurrence recovery belongs in later collectors once the lifecycle
pipeline is proven end-to-end.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json

from d810.capabilities.source_lifter import select_lifter
from d810.core.maturity_labels import WITH_ZERO_MATURITY_VALUES
from d810.core.typing import Any, Iterable
from d810.ir.expressions import ValueOpKind
from d810.ir.instructions import Instruction, InstructionEffectKind
from d810.ir.insn_projection import (
    InstructionProjection,
    diag_row_has_operand_tree,
    project_diag_instruction,
)
from d810.ir.maturity import EARLY_FACT_COLLECTION_IR_MATURITIES
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.ir.varnode import Space, Varnode
from d810.analyses.fact_collection_context import (
    FactCollectionContext,
    coerce_fact_collection_context,
    fact_provider_label,
)
from d810.analyses.value_flow.model import FactObservation

_ADD_OPCODES = frozenset({"op_12", ValueOpKind.ADD.value, ValueOpKind.ADD.name})
_SUB_OPCODES = frozenset({"op_13", ValueOpKind.SUB.value, ValueOpKind.SUB.name})
_STX_OPCODES = frozenset({"op_1", ValueOpKind.STORE.value, ValueOpKind.STORE.name})
_MOV_OPCODES = frozenset({"op_4", "mov", ValueOpKind.MOVE.value, ValueOpKind.MOVE.name})


_MATURITY_VALUES = dict(WITH_ZERO_MATURITY_VALUES)
_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES


@dataclass(frozen=True)
class _InstructionView:
    block_serial: int
    insn_index: int
    ea: int | None
    opcode_name: str
    dest_type: str | None
    dest_stkoff: int | None
    dest_size: int | None
    src_l_type: str | None
    src_l_stkoff: int | None
    src_l_value: int | None
    src_r_type: str | None
    src_r_stkoff: int | None
    src_r_value: int | None
    dstr: str
    operation: ValueOpKind | None = None
    control_transfer: ControlTransferKind | None = None
    predicate_kind: PredicateKind | None = None
    control_target: int | None = None
    call_kind: CallKind | None = None
    call_target: Varnode | None = None
    call_args: tuple[Varnode, ...] = ()
    memory_target: Varnode | None = None
    memory_value: Varnode | None = None
    memory_segment: Varnode | None = None
    source_stkoffs: tuple[int, ...] = ()
    address_stkoffs: tuple[int, ...] = ()
    address_const_values: tuple[int, ...] = ()
    dest_temp: int | None = None
    src_temps: tuple[int, ...] = ()
    # Register identity for operands carried in a register rather than a
    # stack slot (a ``Varnode`` in ``Space.REGISTER``).  ``None`` when the
    # operand is not a register; ``stkoff`` is likewise ``None`` for register
    # operands.  Populated from the lifted operand snapshot's register field, or
    # a ``*_reg`` attribute on a diag-style instruction when present.
    dest_reg: int | None = None
    src_l_reg: int | None = None
    src_r_reg: int | None = None
    # Lifted operand SUBTREE provenance for the left/right
    # operands, retained so operand-tree walkers can inspect a nested
    # sub-operation (e.g. a ``(%var - #N)`` subtract buried inside an
    # ``m_xdu`` / ``m_jge`` expression) at ANY depth.  The flat
    # ``src_l_stkoff`` / ``src_l_value`` fields above only expose the
    # top-level operand; these carry the full structured subtree.  ``None``
    # for diag-style instructions that do not provide a snapshot subtree.
    src_l_mop: "Any | None" = None
    src_r_mop: "Any | None" = None
    attrs: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class _InductionUpdate:
    insn: _InstructionView
    step: int
    source_side: str


@dataclass(frozen=True)
class _MemoryInductionUpdate:
    define_insn: _InstructionView
    store_insn: _InstructionView
    step: int
    source_side: str
    base_stkoff: int | None
    base_token: str | None


@dataclass(frozen=True)
class _WritebackTailUpdate:
    move_insn: _InstructionView
    address_use_insn: _InstructionView
    source_token: str
    dest_token: str


def _signed_step(value: int) -> int:
    # Keep common unsigned immediates readable when IDA reports them as 64-bit.
    value = int(value)
    if value > 0x7FFFFFFFFFFFFFFF:
        return value - (1 << 64)
    return value


def _reg_from_cfg_insn(value: Any) -> int | None:
    return int(value) if value is not None else None


def _canonical_opcode_name(instruction: Instruction) -> str:
    return str(getattr(instruction.operation, "value", instruction.operation) or "")


def _value_op_from_opcode_name(opcode_name: str) -> ValueOpKind | None:
    if opcode_name in _ADD_OPCODES:
        return ValueOpKind.ADD
    if opcode_name in _SUB_OPCODES:
        return ValueOpKind.SUB
    if opcode_name in _STX_OPCODES:
        return ValueOpKind.STORE
    if opcode_name in _MOV_OPCODES:
        return ValueOpKind.MOVE
    return None


def _value_op_from_instruction(instruction: Instruction) -> ValueOpKind | None:
    operation = instruction.operation
    return operation if isinstance(operation, ValueOpKind) else None


def _operation_of_view(insn: _InstructionView) -> ValueOpKind | None:
    return insn.operation or _value_op_from_opcode_name(insn.opcode_name)


def _type_name_from_varnode(vn: Varnode | None) -> str | None:
    if vn is None:
        return None
    return vn.space.value


def _stkoff_from_varnode(vn: Varnode | None) -> int | None:
    return int(vn.offset) if vn is not None and vn.space is Space.STACK else None


def _reg_from_varnode(vn: Varnode | None) -> int | None:
    return int(vn.offset) if vn is not None and vn.space is Space.REGISTER else None


def _temp_from_varnode(vn: Varnode | None) -> int | None:
    return int(vn.offset) if vn is not None and vn.space is Space.TEMP else None


def _const_value_from_varnode(vn: Varnode | None) -> int | None:
    return int(vn.offset) if vn is not None and vn.space is Space.CONST else None


def _size_from_varnode(vn: Varnode | None) -> int | None:
    return int(vn.size) if vn is not None else None


def _store_operands(
    instruction: Instruction,
) -> tuple[Varnode | None, Varnode | None, Varnode | None]:
    memory = instruction.memory
    if memory is not None:
        return memory.target, memory.value, memory.segment
    for effect in instruction.effects:
        if effect.kind is InstructionEffectKind.STORE:
            return effect.target, effect.value, effect.segment
    return None, None, None


def _canonical_operands(
    instruction: Instruction,
) -> tuple[Varnode | None, Varnode | None, Varnode | None]:
    if instruction.operation is ValueOpKind.STORE:
        return _store_operands(instruction)
    left = instruction.inputs[0] if len(instruction.inputs) >= 1 else None
    right = instruction.inputs[1] if len(instruction.inputs) >= 2 else None
    return instruction.result, left, right


def _stack_offsets_from_varnodes(varnodes: Iterable[Varnode]) -> tuple[int, ...]:
    seen: set[int] = set()
    offsets: list[int] = []
    for vn in varnodes:
        if vn.space is not Space.STACK:
            continue
        offset = int(vn.offset)
        if offset in seen:
            continue
        seen.add(offset)
        offsets.append(offset)
    return tuple(offsets)


def _int_tuple(values: object) -> tuple[int, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    seen: set[int] = set()
    offsets: list[int] = []
    for value in values:
        try:
            offset = int(value)
        except (TypeError, ValueError):
            continue
        if offset in seen:
            continue
        seen.add(offset)
        offsets.append(offset)
    return tuple(offsets)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _temps_from_varnodes(varnodes: Iterable[Varnode]) -> tuple[int, ...]:
    seen: set[int] = set()
    temps: list[int] = []
    for vn in varnodes:
        if vn.space is not Space.TEMP:
            continue
        offset = int(vn.offset)
        if offset in seen:
            continue
        seen.add(offset)
        temps.append(offset)
    return tuple(temps)


def _stack_offsets_from_diag_meta(meta_text: object) -> tuple[int, ...]:
    if not isinstance(meta_text, str) or not meta_text:
        return ()
    try:
        payload = json.loads(meta_text)
    except (TypeError, ValueError):
        return ()
    if not isinstance(payload, Mapping):
        return ()

    return _int_tuple(
        payload.get("source_stkoffs")
        or payload.get("source_stack_refs")
        or payload.get("stack_refs")
        or payload.get("stack_offsets")
    )


def _address_stack_offsets_from_diag_meta(meta_text: object) -> tuple[int, ...]:
    if not isinstance(meta_text, str) or not meta_text:
        return ()
    try:
        payload = json.loads(meta_text)
    except (TypeError, ValueError):
        return ()
    if not isinstance(payload, Mapping):
        return ()

    explicit = _int_tuple(
        payload.get("address_stack_refs") or payload.get("address_stkoffs")
    )
    if explicit:
        return explicit

    return ()


def _attrs_from_diag_meta(meta_text: object) -> Mapping[str, Any]:
    if not isinstance(meta_text, str) or not meta_text:
        return {}
    try:
        payload = json.loads(meta_text)
    except (TypeError, ValueError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _control_transfer_from_instruction(
    instruction: Instruction,
) -> ControlTransferKind | None:
    control = instruction.control
    return control.transfer if control is not None else None


def _predicate_kind_from_instruction(instruction: Instruction) -> PredicateKind | None:
    control = instruction.control
    return control.predicate if control is not None else None


def _control_target_from_instruction(instruction: Instruction) -> int | None:
    control = instruction.control
    if control is None or control.target is None:
        return None
    return int(control.target)


def _predicate_kind_from_raw(value: object) -> PredicateKind | None:
    if isinstance(value, PredicateKind):
        return value
    if isinstance(value, str):
        try:
            return PredicateKind(value)
        except ValueError:
            return None
    return None


def _control_transfer_from_raw(value: object) -> ControlTransferKind | None:
    if isinstance(value, ControlTransferKind):
        return value
    if isinstance(value, str):
        try:
            return ControlTransferKind(value)
        except ValueError:
            return None
    return None


def _first_present(*values: object) -> object | None:
    for value in values:
        if value is not None:
            return value
    return None


def _call_kind_from_instruction(instruction: Instruction) -> CallKind | None:
    control = instruction.control
    return control.call_kind if control is not None else None


def _call_target_from_instruction(instruction: Instruction) -> Varnode | None:
    control = instruction.control
    return control.call_target if control is not None else None


def _call_args_from_instruction(instruction: Instruction) -> tuple[Varnode, ...]:
    control = instruction.control
    return control.call_args if control is not None else ()


def _address_stack_offsets_from_instruction(
    instruction: Instruction,
) -> tuple[int, ...]:
    return _int_tuple(instruction.attrs.get("address_stack_refs"))


def _address_const_values_from_instruction(
    instruction: Instruction,
) -> tuple[int, ...]:
    return _int_tuple(instruction.attrs.get("address_const_values"))


def _instruction_view_from_canonical(
    *,
    block_serial: int,
    index: int,
    instruction: Instruction,
) -> _InstructionView:
    dest, left, right = _canonical_operands(instruction)
    attrs = instruction.attrs
    ea_raw = attrs.get("ea")
    ea = int(ea_raw) if ea_raw is not None else None
    memory = instruction.memory
    return _InstructionView(
        block_serial=int(block_serial),
        insn_index=int(index),
        ea=ea,
        opcode_name=_canonical_opcode_name(instruction),
        dest_type=_type_name_from_varnode(dest),
        dest_stkoff=_stkoff_from_varnode(dest),
        dest_size=_size_from_varnode(dest),
        src_l_type=_type_name_from_varnode(left),
        src_l_stkoff=_stkoff_from_varnode(left),
        src_l_value=_const_value_from_varnode(left),
        src_r_type=_type_name_from_varnode(right),
        src_r_stkoff=_stkoff_from_varnode(right),
        src_r_value=_const_value_from_varnode(right),
        dstr=str(attrs.get("display_text") or ""),
        operation=_value_op_from_instruction(instruction),
        control_transfer=_control_transfer_from_instruction(instruction),
        predicate_kind=_predicate_kind_from_instruction(instruction),
        control_target=_control_target_from_instruction(instruction),
        call_kind=_call_kind_from_instruction(instruction),
        call_target=_call_target_from_instruction(instruction),
        call_args=_call_args_from_instruction(instruction),
        memory_target=memory.target if memory is not None else None,
        memory_value=memory.value if memory is not None else None,
        memory_segment=memory.segment if memory is not None else None,
        source_stkoffs=_stack_offsets_from_varnodes(instruction.inputs),
        address_stkoffs=_address_stack_offsets_from_instruction(instruction),
        address_const_values=_address_const_values_from_instruction(instruction),
        dest_temp=_temp_from_varnode(instruction.result),
        src_temps=_temps_from_varnodes(instruction.inputs),
        dest_reg=_reg_from_varnode(dest),
        src_l_reg=_reg_from_varnode(left),
        src_r_reg=_reg_from_varnode(right),
        attrs=attrs,
    )


def _iter_portable_instructions(target: Any) -> Iterable[_InstructionView]:
    blocks = getattr(target, "blocks", target)
    if isinstance(blocks, Mapping):
        block_iter = blocks.values()
    else:
        block_iter = blocks
    for blk in block_iter:
        block_serial = int(getattr(blk, "serial"))
        cfg_instructions = getattr(blk, "insn_snapshots", None)
        if cfg_instructions is not None:
            for index, instruction in enumerate(InstructionProjection.from_block(blk)):
                yield _instruction_view_from_canonical(
                    block_serial=block_serial,
                    index=index,
                    instruction=instruction,
                )
            continue
        for index, insn in enumerate(getattr(blk, "instructions", ())):
            # llr-3b41 S2: a diag Branch-B row that carries a parseable ``meta``
            # operand tree (DB-replay / ``InstructionSnapshot`` rows) is lifted
            # through the SAME canonical projection Branch-A uses, so its
            # operand facts become canonical-faithful (real ``operation``,
            # recursive ``address_stkoffs``).  Meta-less rows -- the production
            # ``mba_to_fact_target`` ``SimpleNamespace`` (flat fields only) and
            # attrs-only ``meta`` rows -- fall through to the byte-identical
            # legacy flat-field path below (canonical reads only the operand
            # tree, never the flat fields, so it cannot reproduce them).
            if diag_row_has_operand_tree(insn):
                canonical = project_diag_instruction(insn)
                view = _instruction_view_from_canonical(
                    block_serial=block_serial,
                    index=int(getattr(insn, "index", index)),
                    instruction=canonical,
                )
                yield view
                continue
            dest_stkoff = (
                int(getattr(insn, "dest_stkoff"))
                if getattr(insn, "dest_stkoff", None) is not None
                else None
            )
            src_l_stkoff = (
                int(getattr(insn, "src_l_stkoff"))
                if getattr(insn, "src_l_stkoff", None) is not None
                else None
            )
            src_r_stkoff = (
                int(getattr(insn, "src_r_stkoff"))
                if getattr(insn, "src_r_stkoff", None) is not None
                else None
            )
            src_l_value = (
                int(getattr(insn, "src_l_value"))
                if getattr(insn, "src_l_value", None) is not None
                else None
            )
            src_r_value = (
                int(getattr(insn, "src_r_value"))
                if getattr(insn, "src_r_value", None) is not None
                else None
            )
            source_stkoffs = tuple(
                dict.fromkeys(
                    int(offset)
                    for offset in (
                        *tuple(getattr(insn, "source_stkoffs", ()) or ()),
                        *_stack_offsets_from_diag_meta(getattr(insn, "meta", None)),
                        src_l_stkoff,
                        src_r_stkoff,
                    )
                    if offset is not None
                )
            )
            address_stkoffs = _address_stack_offsets_from_diag_meta(
                getattr(insn, "meta", None)
            )
            attrs = dict(_attrs_from_diag_meta(getattr(insn, "meta", None)))
            opcode_name = str(getattr(insn, "opcode_name", ""))
            yield _InstructionView(
                block_serial=block_serial,
                insn_index=int(getattr(insn, "index", index)),
                ea=getattr(insn, "ea", None),
                opcode_name=opcode_name,
                dest_type=getattr(insn, "dest_type", None),
                dest_stkoff=dest_stkoff,
                dest_size=getattr(insn, "dest_size", None),
                src_l_type=getattr(insn, "src_l_type", None),
                src_l_stkoff=src_l_stkoff,
                src_l_value=src_l_value,
                src_r_type=getattr(insn, "src_r_type", None),
                src_r_stkoff=src_r_stkoff,
                src_r_value=src_r_value,
                dstr=str(getattr(insn, "dstr", "")),
                operation=_value_op_from_opcode_name(opcode_name),
                control_transfer=_control_transfer_from_raw(
                    _first_present(
                        getattr(insn, "control_transfer", None),
                        getattr(insn, "control_transfer_kind", None),
                        attrs.get("control_transfer"),
                        attrs.get("control_transfer_kind"),
                    )
                ),
                predicate_kind=_predicate_kind_from_raw(
                    _first_present(
                        getattr(insn, "predicate_kind", None),
                        getattr(insn, "branch_predicate", None),
                        attrs.get("predicate_kind"),
                        attrs.get("branch_predicate"),
                    )
                ),
                control_target=_optional_int(
                    _first_present(
                        getattr(insn, "control_target", None),
                        getattr(insn, "branch_target", None),
                        attrs.get("control_target"),
                        attrs.get("branch_target"),
                        attrs.get("target_block"),
                    )
                ),
                source_stkoffs=source_stkoffs,
                address_stkoffs=address_stkoffs,
                address_const_values=_int_tuple(
                    attrs.get("address_const_values")
                    or attrs.get("address_constants")
                ),
                dest_reg=_reg_from_cfg_insn(getattr(insn, "dest_reg", None)),
                src_l_reg=_reg_from_cfg_insn(getattr(insn, "src_l_reg", None)),
                src_r_reg=_reg_from_cfg_insn(getattr(insn, "src_r_reg", None)),
                src_l_mop=getattr(insn, "src_l_mop", None) or getattr(insn, "l", None),
                src_r_mop=getattr(insn, "src_r_mop", None) or getattr(insn, "r", None),
                attrs=attrs,
            )


def _iter_instruction_views(target: Any) -> Iterable[_InstructionView]:
    # LS10: if a backend has registered a live SourceLifter that handles this
    # source, lift it to a portable flow graph first; otherwise fall back to the
    # default snapshot/instruction iteration below -- behavior-identical to
    # pre-LS10 when no lifter is registered.
    lifter = select_lifter(target)
    if lifter is not None:
        target = lifter.lift(target)
    return _iter_portable_instructions(target)


def _classify_induction_update(insn: _InstructionView) -> _InductionUpdate | None:
    operation = _operation_of_view(insn)
    if insn.dest_stkoff is not None:
        if operation is ValueOpKind.ADD:
            if insn.src_l_stkoff == insn.dest_stkoff and insn.src_r_value is not None:
                return _InductionUpdate(insn, _signed_step(insn.src_r_value), "right")
            if insn.src_r_stkoff == insn.dest_stkoff and insn.src_l_value is not None:
                return _InductionUpdate(insn, _signed_step(insn.src_l_value), "left")
        if operation is ValueOpKind.SUB:
            if insn.src_l_stkoff == insn.dest_stkoff and insn.src_r_value is not None:
                return _InductionUpdate(insn, -_signed_step(insn.src_r_value), "right")
        return None
    return _classify_register_induction_update(insn)


def _classify_register_induction_update(
    insn: _InstructionView,
) -> _InductionUpdate | None:
    """Classify a register self-update ``reg = reg +/- const``."""
    if insn.dest_reg is None:
        return None
    operation = _operation_of_view(insn)
    if operation is ValueOpKind.ADD:
        if insn.src_l_reg == insn.dest_reg and insn.src_r_value is not None:
            return _InductionUpdate(insn, _signed_step(insn.src_r_value), "right")
        if insn.src_r_reg == insn.dest_reg and insn.src_l_value is not None:
            return _InductionUpdate(insn, _signed_step(insn.src_l_value), "left")
    if operation is ValueOpKind.SUB:
        if insn.src_l_reg == insn.dest_reg and insn.src_r_value is not None:
            return _InductionUpdate(insn, -_signed_step(insn.src_r_value), "right")
    return None


def _stack_storage_token(stkoff: int | None) -> str | None:
    return None if stkoff is None else f"S{int(stkoff)}"


def _classify_memory_define(
    insn: _InstructionView,
) -> tuple[int, str, tuple[int, ...]] | None:
    if insn.dest_stkoff is None:
        return None
    if not insn.address_stkoffs:
        return None
    operation = _operation_of_view(insn)
    if operation is ValueOpKind.ADD:
        if insn.src_r_value is not None:
            return (_signed_step(insn.src_r_value), "right", insn.address_stkoffs)
        if insn.src_l_value is not None:
            return (_signed_step(insn.src_l_value), "left", insn.address_stkoffs)
    if operation is ValueOpKind.SUB:
        if insn.src_r_value is not None:
            return (-_signed_step(insn.src_r_value), "right", insn.address_stkoffs)
    return None


def _iter_memory_induction_updates(
    instructions: tuple[_InstructionView, ...],
) -> Iterable[_MemoryInductionUpdate]:
    definitions: dict[tuple[int, int], tuple[_InstructionView, int, str, tuple[int, ...]]] = {}
    for insn in instructions:
        mem_def = _classify_memory_define(insn)
        if mem_def is not None and insn.dest_stkoff is not None:
            step, source_side, base_stkoffs = mem_def
            definitions[(insn.block_serial, insn.dest_stkoff)] = (
                insn,
                step,
                source_side,
                base_stkoffs,
            )
            continue
        if (
            _operation_of_view(insn) is not ValueOpKind.STORE
            or insn.src_l_stkoff is None
            or insn.dest_stkoff is None
        ):
            continue
        definition = definitions.get((insn.block_serial, insn.src_l_stkoff))
        if definition is None:
            continue
        define_insn, step, source_side, base_stkoffs = definition
        base_stkoff = int(insn.dest_stkoff)
        if base_stkoff not in base_stkoffs:
            continue
        yield _MemoryInductionUpdate(
            define_insn=define_insn,
            store_insn=insn,
            step=step,
            source_side=source_side,
            base_stkoff=base_stkoff,
            base_token=_stack_storage_token(base_stkoff),
        )


def _stack_move_identity(insn: _InstructionView) -> tuple[int, int] | None:
    if _operation_of_view(insn) is not ValueOpKind.MOVE:
        return None
    if insn.dest_stkoff is None or insn.src_l_stkoff is None:
        return None
    return int(insn.src_l_stkoff), int(insn.dest_stkoff)


def _uses_stack_in_memory_address(insn: _InstructionView, stkoff: int) -> bool:
    return int(stkoff) in {int(offset) for offset in insn.address_stkoffs}


def _iter_writeback_tail_updates(
    instructions: tuple[_InstructionView, ...],
) -> Iterable[_WritebackTailUpdate]:
    by_block: dict[int, list[_InstructionView]] = {}
    for insn in instructions:
        by_block.setdefault(insn.block_serial, []).append(insn)

    for block_instructions in by_block.values():
        ordered = sorted(block_instructions, key=lambda insn: insn.insn_index)
        for index, insn in enumerate(ordered):
            identity = _stack_move_identity(insn)
            if identity is None:
                continue
            source_stkoff, dest_stkoff = identity
            for later in ordered[index + 1:]:
                if _uses_stack_in_memory_address(later, source_stkoff):
                    yield _WritebackTailUpdate(
                        move_insn=insn,
                        address_use_insn=later,
                        source_token=_stack_storage_token(source_stkoff) or "unknown",
                        dest_token=_stack_storage_token(dest_stkoff) or "unknown",
                    )
                    break


class InductionVariableFactCollector:
    """Observe direct stack-variable induction updates across maturities.

    Canonical collector class name for induction-variable source evidence.
    Raw observations still serialize as ``InductionCarrierFact`` because that
    is the source ontology produced by this collector; projected value-flow
    facts serialize as ``InductionVariableFact``.
    """

    name = "InductionVariableFactCollector"
    fact_kinds = frozenset({"InductionCarrierFact"})
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
        func_ea = context.func_ea
        phase = context.phase
        maturity_text = fact_provider_label(context)
        observations: list[FactObservation] = []
        seen: set[tuple[int, int, int, int]] = set()
        instructions = tuple(_iter_instruction_views(target))
        for insn in instructions:
            update = _classify_induction_update(insn)
            if update is None:
                continue
            # The fact is keyed by the induction destination's stack offset; an update
            # whose destination has no stack offset (e.g. a register-only carrier) has no
            # ``stkoff`` key and is skipped rather than crashing ``int(None)`` in
            # ``semantic_key`` below (ticket llr-a93i; the baseline
            # InductionVariableFactCollector failures).
            if insn.dest_stkoff is None:
                continue
            dest_size = int(insn.dest_size or 0)
            dedupe = (
                update.insn.block_serial,
                update.insn.insn_index,
                int(update.insn.dest_stkoff or 0),
                update.step,
            )
            if dedupe in seen:
                continue
            seen.add(dedupe)
            semantic_key = (
                f"induction:stkoff=0x{int(insn.dest_stkoff):x}:"
                f"size={dest_size}:step={update.step}"
            )
            fact_id = (
                f"{semantic_key}:blk={insn.block_serial}:"
                f"insn={insn.insn_index}:ea=0x{int(insn.ea or 0):x}"
            )
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="InductionCarrierFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.9,
                    source_block=insn.block_serial,
                    source_ea=insn.ea,
                    block_fingerprint=(
                        f"blk[{insn.block_serial}].{insn.insn_index}:{insn.opcode_name}"
                    ),
                    mop_signature=f"mop_S:0x{int(insn.dest_stkoff):x}:{dest_size}",
                    payload={
                        "carrier_kind": "stack_self_update",
                        "dest_stkoff": int(insn.dest_stkoff),
                        "dest_size": dest_size,
                        "step": update.step,
                        "opcode": insn.opcode_name,
                        "source_side": update.source_side,
                        "block_serial": insn.block_serial,
                        "insn_index": insn.insn_index,
                    },
                    evidence=(insn.dstr,),
                )
            )
        for update in _iter_memory_induction_updates(instructions):
            store = update.store_insn
            define = update.define_insn
            dest_size = int(define.dest_size or store.dest_size or 0)
            dedupe = (
                store.block_serial,
                store.insn_index,
                int(store.dest_stkoff or 0),
                update.step,
            )
            if dedupe in seen:
                continue
            seen.add(dedupe)
            semantic_key = (
                f"induction:memory_base_stkoff=0x{int(store.dest_stkoff or 0):x}:"
                f"size={dest_size}:step={update.step}"
            )
            fact_id = (
                f"{semantic_key}:blk={store.block_serial}:"
                f"def={define.insn_index}:stx={store.insn_index}:ea=0x{int(store.ea or 0):x}"
            )
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="InductionCarrierFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.82,
                    source_block=store.block_serial,
                    source_ea=store.ea,
                    block_fingerprint=(
                        f"blk[{store.block_serial}].{define.insn_index}->{store.insn_index}:"
                        f"{define.opcode_name}/{store.opcode_name}"
                    ),
                    mop_signature=(
                        f"mop_S:base=0x{int(store.dest_stkoff or 0):x}:"
                        f"tmp=0x{int(store.src_l_stkoff or 0):x}:{dest_size}"
                    ),
                    payload={
                        "carrier_kind": "memory_store_update",
                        "base_stkoff": int(store.dest_stkoff or 0),
                        "temp_stkoff": int(store.src_l_stkoff or 0),
                        "dest_size": dest_size,
                        "step": update.step,
                        "define_opcode": define.opcode_name,
                        "store_opcode": store.opcode_name,
                        "source_side": update.source_side,
                        "block_serial": store.block_serial,
                        "define_insn_index": define.insn_index,
                        "store_insn_index": store.insn_index,
                        "base_token": update.base_token,
                    },
                    evidence=(define.dstr, store.dstr),
                )
            )
        for update in _iter_writeback_tail_updates(instructions):
            move = update.move_insn
            address_use = update.address_use_insn
            dest_size = int(move.dest_size or 0)
            dedupe = (
                move.block_serial,
                move.insn_index,
                int(move.dest_stkoff or 0),
                int(move.src_l_stkoff or 0),
            )
            if dedupe in seen:
                continue
            seen.add(dedupe)
            semantic_key = (
                f"induction:writeback_tail:dest=0x{int(move.dest_stkoff or 0):x}:"
                f"source=0x{int(move.src_l_stkoff or 0):x}:size={dest_size}"
            )
            fact_id = (
                f"{semantic_key}:blk={move.block_serial}:"
                f"mov={move.insn_index}:use={address_use.insn_index}:"
                f"ea=0x{int(move.ea or 0):x}"
            )
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="InductionCarrierFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.78,
                    source_block=move.block_serial,
                    source_ea=move.ea,
                    block_fingerprint=(
                        f"blk[{move.block_serial}].{move.insn_index}->"
                        f"{address_use.insn_index}:writeback_tail"
                    ),
                    mop_signature=(
                        f"mop_S:writeback:dest=0x{int(move.dest_stkoff or 0):x}:"
                        f"source=0x{int(move.src_l_stkoff or 0):x}:{dest_size}"
                    ),
                    payload={
                        "carrier_kind": "writeback_tail",
                        "dest_stkoff": int(move.dest_stkoff or 0),
                        "source_stkoff": int(move.src_l_stkoff or 0),
                        "dest_token": update.dest_token,
                        "source_token": update.source_token,
                        "dest_size": dest_size,
                        "block_serial": move.block_serial,
                        "move_insn_index": move.insn_index,
                        "address_use_insn_index": address_use.insn_index,
                    },
                    evidence=(move.dstr, address_use.dstr),
                )
            )
        return tuple(observations)
