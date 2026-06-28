"""Terminal byte-emitter fact collector.

This collector is observability-only.  It records byte-emitter shaped memory
stores and their local guard/edge context so the diag DB can answer where each
terminal byte step survives, remaps, or disappears across microcode maturities.

llr-3b41 S11 -- the coupled ``terminal_byte_emitter`` / ``return_frontier``
collectors consume the canonical :class:`~d810.ir.instructions.Instruction` IR
through a collector-local canonical-only iterator (:func:`_iter_block_views`).
They share the private :class:`_BlockView` / :func:`_iter_block_views` /
:func:`_block_metadata` helpers defined here, so they are ported together.

The per-block instruction payload (``_BlockView.instructions``) carries the
:class:`_TerminalInsn` record built from a canonical ``Instruction``:
terminal_byte_emitter reads the FULL operand surface (``attrs`` nested
terminal-byte mappings, control transfer / predicate / target, memory
target/value, left/right operand identity for stack/reg/const/temp,
``address_const_values``, ``dstr``).  A meta-rich FlowGraph block (the only
shape a production fact target ever is) is projected via
``InstructionProjection.from_block``; an offline diag row carrying a parseable
``meta`` operand tree is lifted via ``project_diag_instruction``.  The meta-less
flat fallback was removed (S11) -- it was unreachable by any real source once
every production fact target became a canonical ``FlowGraph``.
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
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.ir.varnode import Space, Varnode
from d810.analyses.fact_collection_context import (
    FactCollectionContext,
    coerce_fact_collection_context,
    fact_provider_label,
)
from d810.analyses.value_flow.induction_carrier import (
    _address_const_values_from_instruction,
    _canonical_opcode_name,
    _canonical_operands,
    _const_value_from_varnode,
    _control_target_from_instruction,
    _control_transfer_from_instruction,
    _predicate_kind_from_instruction,
    _reg_from_varnode,
    _stkoff_from_varnode,
    _temp_from_varnode,
    _type_name_from_varnode,
    _value_op_from_instruction,
)
from d810.analyses.value_flow.model import FactObservation


@dataclass(frozen=True)
class _TerminalInsn:
    """Canonical-derived view consumed by terminal_byte_emitter / return_frontier.

    Exposes the operand surface these collectors read (memory target/value,
    left/right operands, control transfer / predicate / target,
    ``address_const_values``, and the ``attrs`` nested terminal-byte mappings).
    Built solely from a canonical :class:`~d810.ir.instructions.Instruction`;
    there is no meta-less fallback.
    """

    block_serial: int
    insn_index: int
    ea: int | None
    opcode_name: str
    dstr: str
    operation: ValueOpKind | None
    control_transfer: ControlTransferKind | None
    predicate_kind: PredicateKind | None
    control_target: int | None
    memory_target: Varnode | None
    memory_value: Varnode | None
    dest_type: str | None
    dest_stkoff: int | None
    dest_temp: int | None
    dest_reg: int | None
    src_l_type: str | None
    src_l_stkoff: int | None
    src_l_value: int | None
    src_l_reg: int | None
    src_r_type: str | None
    src_r_stkoff: int | None
    src_r_value: int | None
    src_r_reg: int | None
    address_const_values: tuple[int, ...]
    attrs: Mapping[str, Any]

    @classmethod
    def from_canonical(
        cls,
        *,
        block_serial: int,
        index: int,
        instruction: Instruction,
    ) -> "_TerminalInsn":
        dest, left, right = _canonical_operands(instruction)
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
            control_transfer=_control_transfer_from_instruction(instruction),
            predicate_kind=_predicate_kind_from_instruction(instruction),
            control_target=_control_target_from_instruction(instruction),
            memory_target=memory.target if memory is not None else None,
            memory_value=memory.value if memory is not None else None,
            dest_type=_type_name_from_varnode(dest),
            dest_stkoff=_stkoff_from_varnode(dest),
            dest_temp=_temp_from_varnode(dest),
            dest_reg=_reg_from_varnode(dest),
            src_l_type=_type_name_from_varnode(left),
            src_l_stkoff=_stkoff_from_varnode(left),
            src_l_value=_const_value_from_varnode(left),
            src_l_reg=_reg_from_varnode(left),
            src_r_type=_type_name_from_varnode(right),
            src_r_stkoff=_stkoff_from_varnode(right),
            src_r_value=_const_value_from_varnode(right),
            src_r_reg=_reg_from_varnode(right),
            address_const_values=_address_const_values_from_instruction(instruction),
            attrs=attrs,
        )


_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES


@dataclass(frozen=True)
class _BlockView:
    serial: int
    start_ea: int | None
    succs: tuple[int, ...]
    preds: tuple[int, ...]
    instructions: tuple[_TerminalInsn, ...]


@dataclass(frozen=True)
class _GuardView:
    byte_index: int
    condition: str
    counter_signature: str
    insn: _TerminalInsn


@dataclass(frozen=True)
class _EmitterCandidate:
    block: _BlockView
    insn: _TerminalInsn
    byte_index: int
    destination: str
    source: str
    counter: str
    guard: _GuardView | None
    guard_condition: str
    emitter_role: str
    confidence: float
    evidence: tuple[str, ...]


def _normal_text(value: str) -> str:
    return " ".join(str(value).strip().split())


def _parse_small_int(value: object) -> int | None:
    try:
        parsed = int(str(value), 0)
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= 6 else None


def _attrs(insn: _TerminalInsn) -> Mapping[str, Any]:
    attrs = getattr(insn, "attrs", None)
    return attrs if isinstance(attrs, Mapping) else {}


def _terminal_attrs(insn: _TerminalInsn) -> Mapping[str, Any]:
    attrs = _attrs(insn)
    for key in ("terminal_byte", "terminal_byte_emit", "byte_emit"):
        nested = attrs.get(key)
        if isinstance(nested, Mapping):
            return nested
    return attrs


def _attr(insn: _TerminalInsn, *keys: str) -> Any:
    terminal = _terminal_attrs(insn)
    attrs = _attrs(insn)
    for key in keys:
        if key in terminal:
            return terminal[key]
        if key in attrs:
            return attrs[key]
    return None


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _small_ints(values: Iterable[object]) -> tuple[int, ...]:
    seen: set[int] = set()
    out: list[int] = []
    for value in values:
        parsed = _parse_small_int(value)
        if parsed is None or parsed in seen:
            continue
        seen.add(parsed)
        out.append(parsed)
    return tuple(out)


def _small_int_attr(insn: _TerminalInsn, *keys: str) -> int | None:
    value = _attr(insn, *keys)
    if isinstance(value, (list, tuple)):
        values = _small_ints(value)
        return values[0] if len(values) == 1 else None
    return _parse_small_int(value)


def _signature_from_varnode(vn: Varnode | None) -> str | None:
    if vn is None:
        return None
    if vn.space is Space.REGISTER:
        return f"r{int(vn.offset)}"
    if vn.space is Space.STACK:
        return f"S{int(vn.offset)}"
    if vn.space is Space.GLOBAL:
        return f"v{int(vn.offset)}"
    if vn.space is Space.LVAR:
        return f"l{int(vn.offset)}"
    if vn.space is Space.TEMP:
        return f"t{int(vn.offset)}"
    if vn.space is Space.CONST:
        return f"#{int(vn.offset)}"
    return None


def _operand_signature(
    *,
    operand_type: str | None,
    stkoff: int | None,
    reg: int | None,
    value: int | None,
    temp: int | None = None,
) -> str | None:
    if reg is not None:
        return f"r{int(reg)}"
    if stkoff is not None:
        return f"S{int(stkoff)}"
    if temp is not None:
        return f"t{int(temp)}"
    if value is not None:
        return f"#{int(value)}"
    if operand_type:
        return str(operand_type)
    return None


def _byte_index_from_instruction(insn: _TerminalInsn) -> int | None:
    explicit = _small_int_attr(insn, "byte_index", "source_byte_index")
    if explicit is not None:
        return explicit
    values = _small_ints(insn.address_const_values)
    return values[0] if len(values) == 1 else None


def _guard_from_instruction(insn: _TerminalInsn) -> _GuardView | None:
    is_branch = insn.control_transfer is ControlTransferKind.CONDITIONAL_BRANCH
    has_guard_attrs = _attr(insn, "guard_byte_index", "guard_counter") is not None
    if not is_branch and not has_guard_attrs:
        return None
    byte_index = _small_int_attr(insn, "guard_byte_index", "byte_index")
    if byte_index is None:
        byte_index = _parse_small_int(insn.src_l_value)
    if byte_index is None:
        byte_index = _parse_small_int(insn.src_r_value)
    if byte_index is None:
        return None
    counter = _attr(insn, "guard_counter", "counter_signature", "counter_carrier")
    if counter is None:
        if _parse_small_int(insn.src_l_value) == byte_index:
            counter = _operand_signature(
                operand_type=insn.src_r_type,
                stkoff=insn.src_r_stkoff,
                reg=insn.src_r_reg,
                value=insn.src_r_value,
            )
        else:
            counter = _operand_signature(
                operand_type=insn.src_l_type,
                stkoff=insn.src_l_stkoff,
                reg=insn.src_l_reg,
                value=insn.src_l_value,
            )
    if counter is None:
        return None
    predicate = insn.predicate_kind.value if insn.predicate_kind is not None else "guard"
    condition = str(
        _attr(insn, "guard_condition", "condition_signature")
        or f"{counter} {predicate} {byte_index}"
    )
    return _GuardView(
        byte_index=byte_index,
        condition=condition,
        counter_signature=str(counter),
        insn=insn,
    )


def _is_byte_emit_store(insn: _TerminalInsn) -> bool:
    return insn.operation is ValueOpKind.STORE


def _memory_destination_signature(insn: _TerminalInsn) -> str:
    explicit = _attr(
        insn,
        "destination_buffer_expression",
        "destination_signature",
        "memory_target_signature",
    )
    if explicit is not None:
        return str(explicit)
    target = _signature_from_varnode(insn.memory_target)
    if target is not None:
        return target
    if insn.dest_stkoff is not None:
        return f"S{int(insn.dest_stkoff)}"
    if insn.dest_reg is not None:
        return f"r{int(insn.dest_reg)}"
    if insn.dest_temp is not None:
        return f"t{int(insn.dest_temp)}"
    return "unknown-destination"


def _source_byte_signature(insn: _TerminalInsn, block: _BlockView) -> str:
    explicit = _attr(
        insn,
        "source_byte_expression",
        "source_signature",
        "memory_value_signature",
    )
    if explicit is not None:
        return str(explicit)
    byte_index = _byte_index_from_instruction(insn)
    if byte_index is not None:
        return f"byte[{byte_index}]"
    value = _signature_from_varnode(insn.memory_value)
    if value is not None:
        return value
    for prior in reversed(block.instructions[: insn.insn_index]):
        prior_index = _byte_index_from_instruction(prior)
        if prior_index is not None:
            return f"byte[{prior_index}]"
    if insn.src_l_stkoff is not None:
        return f"S{int(insn.src_l_stkoff)}"
    if insn.src_l_reg is not None:
        return f"r{int(insn.src_l_reg)}"
    if insn.src_r_stkoff is not None:
        return f"S{int(insn.src_r_stkoff)}"
    if insn.src_r_reg is not None:
        return f"r{int(insn.src_r_reg)}"
    return "unknown-source"


def _guard_for_block(block: _BlockView) -> _GuardView | None:
    for insn in block.instructions:
        guard = _guard_from_instruction(insn)
        if guard is not None:
            return guard
    return None


def _block_metadata(target: Any) -> dict[int, tuple[int | None, tuple[int, ...], tuple[int, ...]]]:
    metadata: dict[int, tuple[int | None, tuple[int, ...], tuple[int, ...]]] = {}
    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, Mapping) else blocks
    for blk in block_iter:
        serial = int(getattr(blk, "serial"))
        start_ea = getattr(blk, "start_ea", None)
        if start_ea is None:
            start_ea = getattr(blk, "start", None)
        succs = tuple(int(succ) for succ in getattr(blk, "succs", ()) or ())
        preds = tuple(int(pred) for pred in getattr(blk, "preds", ()) or ())
        metadata[serial] = (
            int(start_ea) if start_ea is not None else None,
            succs,
            preds,
        )
    return metadata


def _iter_terminal_byte_emitter_insns(target: Any) -> Iterable[_TerminalInsn]:
    """Yield the coupled pair's canonical instruction views.

    llr-3b41 S11 -- canonical-only.  ``terminal_byte_emitter`` /
    ``return_frontier`` read the full operand surface (memory target/value,
    left/right stack/reg/const/temp operands, control transfer/predicate/target,
    ``address_const_values``, ``attrs`` nested terminal-byte mappings), adapted
    to the :class:`_TerminalInsn` record built from a canonical
    :class:`~d810.ir.instructions.Instruction`.  A meta-rich
    :class:`~d810.ir.flowgraph.FlowGraph` block (the only shape a production
    fact target ever is) is projected via ``InstructionProjection.from_block``;
    an offline diag row carrying a parseable ``meta`` operand tree is lifted via
    ``project_diag_instruction``.  The meta-less flat fallback was removed -- it
    was unreachable by any real source once every production fact target became
    a canonical ``FlowGraph``.  A registered live
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
            yield _TerminalInsn.from_canonical(
                block_serial=block_serial,
                index=index,
                instruction=instruction,
            )


def _iter_block_views(target: Any) -> Iterable[_BlockView]:
    by_block: dict[int, list[_TerminalInsn]] = {}
    for insn in _iter_terminal_byte_emitter_insns(target):
        by_block.setdefault(insn.block_serial, []).append(insn)

    metadata = _block_metadata(target)
    for serial, instructions in sorted(by_block.items()):
        ordered = tuple(sorted(instructions, key=lambda insn: insn.insn_index))
        start_ea, succs, preds = metadata.get(serial, (None, (), ()))
        yield _BlockView(
            serial=serial,
            start_ea=start_ea,
            succs=succs,
            preds=preds,
            instructions=ordered,
        )


def _continuation_edge(block: _BlockView) -> int | None:
    return block.succs[0] if block.succs else None


def _return_edge(block: _BlockView, guard: _GuardView | None) -> int | None:
    if not block.succs:
        return block.serial
    if guard is None:
        return None
    target = _jump_target(guard.insn)
    if target is not None and target in block.succs:
        if guard.byte_index == 0 and _branch_takes_nonzero(guard.insn):
            for succ in block.succs:
                if succ != target:
                    return succ
        return target
    return None


def _jump_target(insn: _TerminalInsn) -> int | None:
    if insn.control_target is not None:
        return int(insn.control_target)
    return _optional_int(_attr(insn, "control_target", "branch_target", "target_block"))


def _branch_takes_nonzero(insn: _TerminalInsn) -> bool:
    opcode = _attr(insn, "branch_opcode", "jump_opcode")
    if opcode is not None and str(opcode).lower() == "jnz":
        return True
    return insn.predicate_kind in {PredicateKind.NE, PredicateKind.TRUTHY}


def _continuation_edge_for_return(block: _BlockView, return_edge: int | None) -> int | None:
    if not block.succs:
        return None
    if return_edge is None:
        return block.succs[0] if len(block.succs) == 1 else None
    for succ in block.succs:
        if succ != return_edge:
            return succ
    return None


def _terminal_family_id(
    candidate: _EmitterCandidate,
    terminal_counters: frozenset[str],
    terminal_blocks: frozenset[int],
    terminal_destinations: frozenset[str],
) -> str:
    if candidate.counter in terminal_counters:
        return "terminal_tail"
    if candidate.byte_index == 1 and candidate.destination in terminal_destinations:
        return "terminal_tail"
    if (
        candidate.byte_index == 6
        and candidate.counter == "unknown-counter"
        and bool(set(candidate.block.preds) & terminal_blocks)
    ):
        return "terminal_tail"
    return "non_terminal_byte_emitter"


class TerminalByteEmitterFactCollector:
    """Observe terminal byte-emitter memory stores across maturities."""

    name = "TerminalByteEmitterFactCollector"
    fact_kinds = frozenset({"TerminalByteEmitterFact"})
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
        candidates: list[_EmitterCandidate] = []
        seen: set[tuple[int, int, str]] = set()
        store_counters: set[str] = set()
        zero_guard_candidates: list[tuple[_BlockView, _GuardView]] = []

        for block in _iter_block_views(target):
            guard = _guard_for_block(block)
            emitted_in_block = False
            for insn in block.instructions:
                if not _is_byte_emit_store(insn):
                    continue
                explicit_index = _byte_index_from_instruction(insn)
                byte_index = explicit_index
                if byte_index is None and guard is not None:
                    byte_index = guard.byte_index
                if byte_index is None:
                    continue

                destination = _memory_destination_signature(insn)
                source = _source_byte_signature(insn, block)
                counter = guard.counter_signature if guard is not None else "unknown-counter"
                guard_condition = guard.condition if guard is not None else "unknown-guard"
                if byte_index != 0 and counter != "unknown-counter":
                    store_counters.add(counter)
                dedupe = (
                    block.serial,
                    insn.insn_index,
                    f"{byte_index}:{destination}:{counter}",
                )
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                emitted_in_block = True
                candidates.append(
                    _EmitterCandidate(
                        block=block,
                        insn=insn,
                        byte_index=byte_index,
                        destination=destination,
                        source=source,
                        counter=counter,
                        guard=guard,
                        guard_condition=guard_condition,
                        emitter_role="memory_store",
                        confidence=0.72 if guard is not None else 0.62,
                        evidence=tuple(
                            view.dstr
                            for view in block.instructions
                            if view is insn or _guard_from_instruction(view) is not None
                        ),
                    )
                )
            if emitted_in_block or guard is None or guard.byte_index != 0:
                continue
            zero_guard_candidates.append((block, guard))

        for block, guard in zero_guard_candidates:
            counter = guard.counter_signature
            if counter not in store_counters:
                continue
            semantic_key = (
                "terminal_byte_emitter:byte_index=0:"
                f"dest=guard-only:counter={counter}"
            )
            mop_signature = (
                "terminal_byte_emit:byte=0:"
                f"dest=guard-only:counter={counter}"
            )
            dedupe = (block.serial, guard.insn.insn_index, semantic_key)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            candidates.append(
                _EmitterCandidate(
                    block=block,
                    insn=guard.insn,
                    byte_index=0,
                    destination="guard-only",
                    source="guard-only",
                    counter=counter,
                    guard=guard,
                    guard_condition=guard.condition,
                    emitter_role="guard_only",
                    confidence=0.54,
                    evidence=(guard.insn.dstr,),
                )
            )

        terminal_counters = frozenset(
            candidate.counter
            for candidate in candidates
            if candidate.emitter_role == "guard_only" and candidate.byte_index == 0
        )
        terminal_blocks = frozenset(
            candidate.block.serial
            for candidate in candidates
            if candidate.counter in terminal_counters
        )
        terminal_destinations = frozenset(
            candidate.destination
            for candidate in candidates
            if (
                candidate.counter in terminal_counters
                and candidate.emitter_role == "memory_store"
                and candidate.destination != "guard-only"
            )
        )

        observations: list[FactObservation] = []
        for candidate in candidates:
            family_id = _terminal_family_id(
                candidate,
                terminal_counters,
                terminal_blocks,
                terminal_destinations,
            )
            block = candidate.block
            insn = candidate.insn
            semantic_key = (
                f"terminal_byte_emitter:family={family_id}:"
                f"byte_index={candidate.byte_index}:"
                f"dest={candidate.destination}:counter={candidate.counter}"
            )
            mop_signature = (
                f"terminal_byte_emit:family={family_id}:"
                f"byte={candidate.byte_index}:"
                f"dest={candidate.destination}:counter={candidate.counter}"
            )
            fact_id = (
                f"{semantic_key}:blk={block.serial}:"
                f"insn={insn.insn_index}:ea=0x{int(insn.ea or 0):x}"
            )
            return_edge = _return_edge(block, candidate.guard)
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="TerminalByteEmitterFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=candidate.confidence,
                    source_block=block.serial,
                    source_ea=insn.ea,
                    block_fingerprint=(
                        f"blk[{block.serial}].{insn.insn_index}:"
                        f"{insn.opcode_name}"
                    ),
                    mop_signature=mop_signature,
                    payload={
                        "family_id": family_id,
                        "corridor_role": family_id,
                        "byte_index": candidate.byte_index,
                        "source_byte_expression": candidate.source,
                        "source_block": block.serial,
                        "destination_buffer_expression": candidate.destination,
                        "destination_block": block.serial,
                        "counter_carrier": candidate.counter,
                        "guard_condition": candidate.guard_condition,
                        "guard_block": (
                            candidate.guard.insn.block_serial
                            if candidate.guard is not None
                            else None
                        ),
                        "guard_insn_index": (
                            candidate.guard.insn.insn_index
                            if candidate.guard is not None
                            else None
                        ),
                        "return_edge": return_edge,
                        "continuation_edge": _continuation_edge_for_return(
                            block,
                            return_edge,
                        ),
                        "successor_blocks": list(block.succs),
                        "predecessor_blocks": list(block.preds),
                        "block_serial": block.serial,
                        "block_ea": block.start_ea,
                        "insn_index": insn.insn_index,
                        "opcode": insn.opcode_name,
                        "emitter_role": candidate.emitter_role,
                    },
                    evidence=candidate.evidence,
                )
            )
        return tuple(observations)


__all__ = ["TerminalByteEmitterFactCollector"]
