"""Induction-carrier fact collector.

The first vertical collector is deliberately conservative: it records direct
stack-variable self updates, such as ``x = x + 0x80`` or ``x = x - 1``.  More
complex recurrence recovery belongs in later collectors once the lifecycle
substrate is proven end-to-end.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from d810.core.typing import Any, Iterable
from d810.recon.facts.model import FactObservation

_ADD_OPCODES = frozenset({"m_add", "op_12"})
_SUB_OPCODES = frozenset({"m_sub", "op_13"})
_STX_OPCODES = frozenset({"m_stx", "op_1"})

_DEREF_BASE_RE = re.compile(r"\[ds\.\d+:%var_([0-9a-fA-F]+)\.\d+\]")
_STX_BASE_RE = re.compile(r"^\s*stx\s+%var_[0-9a-fA-F]+\.\d+,\s*ds\.\d+,\s*%var_([0-9a-fA-F]+)\.\d+")
_STACK_MOV_RE = re.compile(
    r"^\s*mov\s+%var_([0-9a-fA-F]+)\.\d+(?:\{[^}]*\})?\s*,\s*%var_([0-9a-fA-F]+)\.\d+(?:\{[^}]*\})?"
)
_DS_ADDRESS_RE = re.compile(r"\[ds\.[^\]]+\]")


def _maturity_constant(name: str, fallback: int) -> int:
    try:
        import ida_hexrays  # type: ignore

        return int(getattr(ida_hexrays, name))
    except Exception:
        return fallback


_MATURITY_VALUES = {
    "MMAT_GENERATED": _maturity_constant("MMAT_GENERATED", 0),
    "MMAT_PREOPTIMIZED": _maturity_constant("MMAT_PREOPTIMIZED", 1),
    "MMAT_LOCOPT": _maturity_constant("MMAT_LOCOPT", 2),
    "MMAT_CALLS": _maturity_constant("MMAT_CALLS", 3),
    "MMAT_GLBOPT1": _maturity_constant("MMAT_GLBOPT1", 4),
    "MMAT_GLBOPT2": _maturity_constant("MMAT_GLBOPT2", 5),
    "MMAT_GLBOPT3": _maturity_constant("MMAT_GLBOPT3", 6),
    "MMAT_LVARS": _maturity_constant("MMAT_LVARS", 7),
}

_MATURITY_NAMES = {value: name for name, value in _MATURITY_VALUES.items()}
_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})


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
    base_token: str | None


@dataclass(frozen=True)
class _WritebackTailUpdate:
    move_insn: _InstructionView
    address_use_insn: _InstructionView
    source_token: str
    dest_token: str


def _maturity_name(maturity: int) -> str:
    return _MATURITY_NAMES.get(int(maturity), f"MMAT_{int(maturity)}")


def _signed_step(value: int) -> int:
    # Keep common unsigned immediates readable when IDA reports them as 64-bit.
    value = int(value)
    if value > 0x7FFFFFFFFFFFFFFF:
        return value - (1 << 64)
    return value


def _opcode_name_from_live(opcode: int) -> str:
    try:
        import ida_hexrays  # type: ignore

        if opcode == ida_hexrays.m_add:
            return "m_add"
        if opcode == ida_hexrays.m_sub:
            return "m_sub"
        if opcode == ida_hexrays.m_stx:
            return "m_stx"
    except Exception:
        pass
    return f"op_{int(opcode)}"


def _stack_offset_from_mop(mop: Any) -> int | None:
    try:
        import ida_hexrays  # type: ignore

        if getattr(mop, "t", None) == ida_hexrays.mop_S:
            return int(mop.s.off)
    except Exception:
        pass
    return None


def _mop_type_name(mop: Any) -> str | None:
    try:
        import ida_hexrays  # type: ignore

        t = getattr(mop, "t", None)
        if t == ida_hexrays.mop_S:
            return "mop_S"
        if t == ida_hexrays.mop_n:
            return "mop_n"
        if t == ida_hexrays.mop_d:
            return "mop_d"
        if t == ida_hexrays.mop_r:
            return "mop_r"
        if t == ida_hexrays.mop_b:
            return "mop_b"
    except Exception:
        pass
    return None


def _const_value_from_mop(mop: Any) -> int | None:
    try:
        import ida_hexrays  # type: ignore

        if getattr(mop, "t", None) == ida_hexrays.mop_n:
            return int(mop.nnn.value)
    except Exception:
        pass
    return None


def _iter_portable_instructions(target: Any) -> Iterable[_InstructionView]:
    blocks = getattr(target, "blocks", target)
    if isinstance(blocks, dict):
        block_iter = blocks.values()
    else:
        block_iter = blocks
    for blk in block_iter:
        block_serial = int(getattr(blk, "serial"))
        for index, insn in enumerate(getattr(blk, "instructions", ())):
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
            yield _InstructionView(
                block_serial=block_serial,
                insn_index=int(getattr(insn, "index", index)),
                ea=getattr(insn, "ea", None),
                opcode_name=str(getattr(insn, "opcode_name", "")),
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
            )


def _iter_live_instructions(mba: Any) -> Iterable[_InstructionView]:
    qty = int(getattr(mba, "qty", 0) or 0)
    for block_index in range(qty):
        blk = mba.get_mblock(block_index)
        if blk is None:
            continue
        block_serial = int(getattr(blk, "serial", block_index))
        insn = getattr(blk, "head", None)
        insn_index = 0
        while insn is not None:
            try:
                dstr = insn.dstr()
            except Exception:
                dstr = ""
            yield _InstructionView(
                block_serial=block_serial,
                insn_index=insn_index,
                ea=int(getattr(insn, "ea", 0) or 0),
                opcode_name=_opcode_name_from_live(int(getattr(insn, "opcode", -1))),
                dest_type=_mop_type_name(getattr(insn, "d", None)),
                dest_stkoff=_stack_offset_from_mop(getattr(insn, "d", None)),
                dest_size=getattr(getattr(insn, "d", None), "size", None),
                src_l_type=_mop_type_name(getattr(insn, "l", None)),
                src_l_stkoff=_stack_offset_from_mop(getattr(insn, "l", None)),
                src_l_value=_const_value_from_mop(getattr(insn, "l", None)),
                src_r_type=_mop_type_name(getattr(insn, "r", None)),
                src_r_stkoff=_stack_offset_from_mop(getattr(insn, "r", None)),
                src_r_value=_const_value_from_mop(getattr(insn, "r", None)),
                dstr=str(dstr),
            )
            insn = getattr(insn, "next", None)
            insn_index += 1


def _iter_instruction_views(target: Any) -> Iterable[_InstructionView]:
    if hasattr(target, "qty") and hasattr(target, "get_mblock"):
        return _iter_live_instructions(target)
    return _iter_portable_instructions(target)


def _classify_induction_update(insn: _InstructionView) -> _InductionUpdate | None:
    if insn.dest_stkoff is None:
        return None
    if insn.opcode_name in _ADD_OPCODES:
        if insn.src_l_stkoff == insn.dest_stkoff and insn.src_r_value is not None:
            return _InductionUpdate(insn, _signed_step(insn.src_r_value), "right")
        if insn.src_r_stkoff == insn.dest_stkoff and insn.src_l_value is not None:
            return _InductionUpdate(insn, _signed_step(insn.src_l_value), "left")
    if insn.opcode_name in _SUB_OPCODES:
        if insn.src_l_stkoff == insn.dest_stkoff and insn.src_r_value is not None:
            return _InductionUpdate(insn, -_signed_step(insn.src_r_value), "right")
    return None


def _deref_base_token(dstr: str) -> str | None:
    match = _DEREF_BASE_RE.search(dstr)
    if match is None:
        return None
    return match.group(1).lower()


def _stx_base_token(dstr: str) -> str | None:
    match = _STX_BASE_RE.search(dstr)
    if match is None:
        return None
    return match.group(1).lower()


def _classify_memory_define(insn: _InstructionView) -> tuple[int, str, str | None] | None:
    if insn.dest_stkoff is None:
        return None
    base_token = _deref_base_token(insn.dstr)
    if base_token is None:
        return None
    if insn.opcode_name in _ADD_OPCODES:
        if insn.src_r_value is not None:
            return (_signed_step(insn.src_r_value), "right", base_token)
        if insn.src_l_value is not None:
            return (_signed_step(insn.src_l_value), "left", base_token)
    if insn.opcode_name in _SUB_OPCODES:
        if insn.src_r_value is not None:
            return (-_signed_step(insn.src_r_value), "right", base_token)
    return None


def _iter_memory_induction_updates(
    instructions: tuple[_InstructionView, ...],
) -> Iterable[_MemoryInductionUpdate]:
    definitions: dict[tuple[int, int], tuple[_InstructionView, int, str, str | None]] = {}
    for insn in instructions:
        mem_def = _classify_memory_define(insn)
        if mem_def is not None and insn.dest_stkoff is not None:
            step, source_side, base_token = mem_def
            definitions[(insn.block_serial, insn.dest_stkoff)] = (
                insn,
                step,
                source_side,
                base_token,
            )
            continue
        if (
            insn.opcode_name not in _STX_OPCODES
            or insn.src_l_stkoff is None
            or insn.dest_stkoff is None
        ):
            continue
        definition = definitions.get((insn.block_serial, insn.src_l_stkoff))
        if definition is None:
            continue
        define_insn, step, source_side, base_token = definition
        store_base_token = _stx_base_token(insn.dstr)
        if base_token is not None and store_base_token is not None and base_token != store_base_token:
            continue
        yield _MemoryInductionUpdate(
            define_insn=define_insn,
            store_insn=insn,
            step=step,
            source_side=source_side,
            base_token=base_token,
        )


def _stack_mov_tokens(insn: _InstructionView) -> tuple[str, str] | None:
    if insn.opcode_name not in {"m_mov", "op_4"}:
        return None
    if insn.dest_stkoff is None or insn.src_l_stkoff is None:
        return None
    match = _STACK_MOV_RE.search(insn.dstr)
    if match is None:
        return None
    return (match.group(1).lower(), match.group(2).lower())


def _uses_token_in_memory_address(insn: _InstructionView, token: str) -> bool:
    text = insn.dstr.lower()
    token_text = f"%var_{token.lower()}."
    return any(
        token_text in match.group(0)
        for match in _DS_ADDRESS_RE.finditer(text)
    )


def _iter_writeback_tail_updates(
    instructions: tuple[_InstructionView, ...],
) -> Iterable[_WritebackTailUpdate]:
    by_block: dict[int, list[_InstructionView]] = {}
    for insn in instructions:
        by_block.setdefault(insn.block_serial, []).append(insn)

    for block_instructions in by_block.values():
        ordered = sorted(block_instructions, key=lambda insn: insn.insn_index)
        for index, insn in enumerate(ordered):
            tokens = _stack_mov_tokens(insn)
            if tokens is None:
                continue
            source_token, dest_token = tokens
            for later in ordered[index + 1:]:
                if _uses_token_in_memory_address(later, source_token):
                    yield _WritebackTailUpdate(
                        move_insn=insn,
                        address_use_insn=later,
                        source_token=source_token,
                        dest_token=dest_token,
                    )
                    break


class InductionVariableFactCollector:
    """Observe direct stack-variable induction updates across maturities.

    Canonical collector class name for induction-variable source evidence.
    ``InductionCarrierFactCollector`` remains available as an import alias
    only; projected value-flow facts serialize as ``InductionVariableFact``.
    """

    name = "InductionVariableFactCollector"
    fact_kinds = frozenset({"InductionCarrierFact"})
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
        seen: set[tuple[int, int, int, int]] = set()
        instructions = tuple(_iter_instruction_views(target))
        for insn in instructions:
            update = _classify_induction_update(insn)
            if update is None:
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


# Legacy class name kept as an alias during the value-flow rename. Phase 4
# class rename is mechanical; the same object answers to both spellings.
InductionCarrierFactCollector = InductionVariableFactCollector
