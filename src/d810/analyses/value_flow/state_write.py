"""Portable state-write constant folding (value-flow).

Extracted from ``d810.backends.hexrays.evidence.condition_chain_analysis`` in the LS6 condition-chain split
(Landing Sequence step 6 / ticket d81-1w16).  This is the PURE constant-folding
core of the condition-chain handler-chain walker: forward evaluation of microcode
instructions to recover the constant value written to a state variable.

Portable-core: no IDA / Hex-Rays imports.  Everything vendor-specific is
lifted by the caller before entering this module.  The Hex-Rays evidence
adapter captures live operands/instructions into portable snapshots and this
module evaluates canonical ``Instruction`` records, preserving raw backend
details only as provenance.

The kill/overwrite semantics are preserved verbatim from the original
walker: ``_store_to_dest`` overwrites the stack/register maps even on an
unresolved source, and an unresolved operand yields ``None`` (a wrong
meet/init here silently wipes folded constants at control-flow merges).
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Callable, Dict, List, Optional
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import InsnSnapshot
from d810.ir.insn_projection import project_instruction_sequence
from d810.ir.instructions import Instruction, InstructionEffectKind
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot


@dataclass(frozen=True)
class MicrocodeEvalSeams:
    """Transitional backend callbacks for non-structural value reads.

    Older call sites still construct this object, so the vocabulary callbacks
    remain part of the shape for compatibility.  Portable evaluation no longer
    switches on them; it consumes lifted snapshots/canonical instructions and
    only uses ``fetch_stable_global_value`` for backend-owned global reads.
    """

    mop_type_name: Callable[[object], Optional[str]]
    mop_type_value: Callable[[str, Optional[int]], Optional[int]]
    opcode_value: Callable[[str, Optional[int]], Optional[int]]
    opcode_name: Callable[[object], Optional[str]]
    fetch_stable_global_value: Callable[[int, int], Optional[int]]
    lvar_stkoff: Callable[[object, int], int]


def resolve_varnode_from_maps(
    varnode: Varnode | None,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    *,
    foldable_global_reads: Optional[Dict[int, Dict[int, int]]] = None,
    fetch_stable_global_value: Callable[[int, int], Optional[int]] | None = None,
    read_ea: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
) -> Optional[int]:
    """Resolve a canonical ``Varnode`` to a concrete value.

    This is the portable state-write evaluator surface.  It consumes the lifted
    operand space directly instead of asking the caller for Hex-Rays-shaped mop
    type names.
    """
    if varnode is None:
        return None

    result: Optional[int] = None
    space = varnode.space
    key = int(varnode.offset)

    if space is Space.CONST:
        result = key
    elif space is Space.STACK:
        result = stk_map.get(key)
    elif space in {Space.REGISTER, Space.TEMP}:
        result = reg_map.get(key)
    elif space is Space.LVAR:
        result = stk_map.get(key)
    elif space is Space.GLOBAL:
        if key in stk_map:
            result = stk_map[key]
        elif foldable_global_reads is not None and read_ea is not None:
            init = foldable_global_reads.get(int(read_ea), {}).get(key)
            if init is not None:
                result = int(init)
            elif fetch_stable_global_value is not None:
                result = fetch_stable_global_value(key, int(varnode.size or 0))
        elif fetch_stable_global_value is not None:
            result = fetch_stable_global_value(key, int(varnode.size or 0))

    if diag_lines is not None:
        diag_lines.append(
            "  fwd_resolve: "
            f"varnode={space.value}{key} -> "
            f"{hex(result) if result is not None else 'None'}"
        )
    return result


def _binary_result(
    operation: ValueOpKind,
    left: int,
    right: int,
) -> Optional[int]:
    if operation is ValueOpKind.XOR:
        return left ^ right
    if operation is ValueOpKind.SUB:
        return left - right
    if operation is ValueOpKind.ADD:
        return left + right
    if operation is ValueOpKind.AND:
        return left & right
    if operation is ValueOpKind.OR:
        return left | right
    if operation is ValueOpKind.MUL:
        return left * right
    return None


def _extended_result(
    operation: ValueOpKind,
    source_value: int,
    *,
    source_size: int,
    output_size: int,
) -> Optional[int]:
    if operation is ValueOpKind.ZEXT:
        return int(source_value) & ((1 << (max(output_size, 1) * 8)) - 1)
    if operation is ValueOpKind.SEXT:
        in_size = max(int(source_size or 0), 1)
        out_size = max(int(output_size or in_size), in_size)
        sign_bit = 1 << (in_size * 8 - 1)
        value = int(source_value)
        if value & sign_bit:
            value |= ((1 << (out_size * 8)) - 1) ^ ((1 << (in_size * 8)) - 1)
        return value & ((1 << (out_size * 8)) - 1)
    return None


def _instruction_store_target(instruction: Instruction) -> Varnode | None:
    if instruction.memory is not None and instruction.memory.target is not None:
        return instruction.memory.target
    for effect in instruction.effects:
        if effect.kind is InstructionEffectKind.STORE:
            return effect.target
    return instruction.result


def _instruction_store_value(instruction: Instruction) -> Varnode | None:
    if instruction.memory is not None and instruction.memory.value is not None:
        return instruction.memory.value
    for effect in instruction.effects:
        if effect.kind is InstructionEffectKind.STORE:
            return effect.value
    if instruction.inputs:
        return instruction.inputs[0]
    return None


def _store_varnode_value(
    dest: Varnode | None,
    value: int,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    state_var_stkoff: int,
    *,
    state_var_gaddr: Optional[int] = None,
) -> bool:
    if dest is None:
        return False
    key = int(dest.offset)
    if dest.space is Space.GLOBAL:
        stk_map[key] = value
        return state_var_gaddr is not None and key == int(state_var_gaddr)
    if dest.space is Space.STACK:
        stk_map[key] = value
        return key == int(state_var_stkoff)
    if dest.space in {Space.REGISTER, Space.TEMP}:
        reg_map[key] = value
        return False
    if dest.space is Space.LVAR:
        stk_map[key] = value
        return key == int(state_var_stkoff)
    return False


def forward_eval_instruction(
    instruction: Instruction,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    state_var_stkoff: int,
    *,
    diag_lines: Optional[List[str]] = None,
    state_var_gaddr: Optional[int] = None,
    foldable_global_reads: Optional[Dict[int, Dict[int, int]]] = None,
    fetch_stable_global_value: Callable[[int, int], Optional[int]] | None = None,
) -> Optional[int]:
    """Evaluate one canonical instruction and update forward maps in-place."""
    read_ea: Optional[int] = None
    try:
        ea_val = instruction.attrs.get("ea")
        if ea_val is not None:
            read_ea = int(ea_val)
    except (TypeError, ValueError):
        read_ea = None

    operation = instruction.operation
    if not isinstance(operation, ValueOpKind):
        return None

    def resolve(varnode: Varnode | None) -> Optional[int]:
        return resolve_varnode_from_maps(
            varnode,
            stk_map,
            reg_map,
            foldable_global_reads=foldable_global_reads,
            fetch_stable_global_value=fetch_stable_global_value,
            read_ea=read_ea,
            diag_lines=diag_lines,
        )

    dest = instruction.result
    val: Optional[int] = None

    if operation is ValueOpKind.STORE:
        dest = _instruction_store_target(instruction)
        val = resolve(_instruction_store_value(instruction))
    elif operation is ValueOpKind.MOVE:
        val = resolve(instruction.inputs[0] if instruction.inputs else None)
    elif operation in {ValueOpKind.ZEXT, ValueOpKind.SEXT}:
        source = instruction.inputs[0] if instruction.inputs else None
        source_value = resolve(source)
        if source_value is not None:
            val = _extended_result(
                operation,
                source_value,
                source_size=int(source.size if source is not None else 4),
                output_size=int(dest.size if dest is not None else 4),
            )
    elif operation in {
        ValueOpKind.ADD,
        ValueOpKind.SUB,
        ValueOpKind.AND,
        ValueOpKind.OR,
        ValueOpKind.XOR,
        ValueOpKind.MUL,
    }:
        left = resolve(instruction.inputs[0] if len(instruction.inputs) >= 1 else None)
        right = resolve(instruction.inputs[1] if len(instruction.inputs) >= 2 else None)
        if left is not None and right is not None:
            val = _binary_result(operation, left, right)
    else:
        return None

    if val is None:
        return None

    val = int(val) & 0xFFFFFFFF
    if _store_varnode_value(
        dest,
        val,
        stk_map,
        reg_map,
        state_var_stkoff,
        state_var_gaddr=state_var_gaddr,
    ):
        if diag_lines is not None:
            diag_lines.append(
                f"  fwd_eval_insn: {operation.value} -> state_var write 0x{val:x}"
            )
        return val
    return None


def get_mop_const_value(
    mop: object,
    *,
    mop_type_name: Callable[[object], Optional[str]] | None = None,
) -> Optional[int]:
    """Extract a constant integer value from a lifted operand snapshot."""
    varnode = varnode_from_mop_snapshot(mop)  # type: ignore[arg-type]
    if varnode is None or varnode.space is not Space.CONST:
        return None
    return int(varnode.offset)


def resolve_mop_from_maps(
    mop: object,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    *,
    seams: MicrocodeEvalSeams | None = None,
    mba: Optional[object] = None,
    state_var_lvar_idx: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
    state_var_gaddr: Optional[int] = None,
    foldable_global_reads: Optional[Dict[int, Dict[int, int]]] = None,
    read_ea: Optional[int] = None,
) -> Optional[int]:
    """Resolve a lifted operand snapshot through accumulated forward-eval maps.

    ``state_var_gaddr`` names a *global* dispatcher state variable: a read of
    that global resolves through ``stk_map`` (keyed by gaddr) like a stack slot,
    so the handler's own next-state write folds.  ``foldable_global_reads`` maps
    ``read_ea -> {gaddr: initializer}`` (reaching-defs-sound, see
    :mod:`d810.analyses.value_flow.global_init_fold`): a global read at
    ``read_ea`` whose gaddr is listed folds to its static ``.data`` initializer
    -- the only value that can be live there because no store reaches it.
    """
    fetch = seams.fetch_stable_global_value if seams is not None else None
    return resolve_varnode_from_maps(
        varnode_from_mop_snapshot(mop),  # type: ignore[arg-type]
        stk_map,
        reg_map,
        foldable_global_reads=foldable_global_reads,
        fetch_stable_global_value=fetch,
        read_ea=read_ea,
        diag_lines=diag_lines,
    )


def _forward_eval_instruction_sequence(
    instructions: tuple[Instruction, ...],
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    state_var_stkoff: int,
    *,
    diag_lines: Optional[List[str]] = None,
    state_var_gaddr: Optional[int] = None,
    foldable_global_reads: Optional[Dict[int, Dict[int, int]]] = None,
    fetch_stable_global_value: Callable[[int, int], Optional[int]] | None = None,
) -> Optional[int]:
    result: Optional[int] = None
    for instruction in instructions:
        value = forward_eval_instruction(
            instruction,
            stk_map,
            reg_map,
            state_var_stkoff,
            diag_lines=diag_lines,
            state_var_gaddr=state_var_gaddr,
            foldable_global_reads=foldable_global_reads,
            fetch_stable_global_value=fetch_stable_global_value,
        )
        if value is not None:
            result = value
    return result


def forward_eval_insn(
    insn: object,
    stk_map: Dict[int, int],
    reg_map: Dict[int, int],
    state_var_stkoff: int,
    *,
    seams: MicrocodeEvalSeams | None = None,
    mba: Optional[object] = None,
    state_var_lvar_idx: Optional[int] = None,
    diag_lines: Optional[List[str]] = None,
    state_var_gaddr: Optional[int] = None,
    foldable_global_reads: Optional[Dict[int, Dict[int, int]]] = None,
) -> Optional[int]:
    """Evaluate one instruction, updating stk_map/reg_map in-place.

    Returns the resolved constant if this instruction writes the state
    variable; otherwise returns None and updates the maps.

    ``state_var_gaddr`` / ``foldable_global_reads`` enable a *global* dispatcher
    state variable (see :func:`resolve_mop_from_maps`): a write to that global is
    treated as the state-var write, and a reaching-defs-stable global read folds
    to its static initializer.
    """
    if insn is None:
        return None

    fetch = seams.fetch_stable_global_value if seams is not None else None

    if isinstance(insn, Instruction):
        return forward_eval_instruction(
            insn,
            stk_map,
            reg_map,
            state_var_stkoff,
            diag_lines=diag_lines,
            state_var_gaddr=state_var_gaddr,
            foldable_global_reads=foldable_global_reads,
            fetch_stable_global_value=fetch,
        )

    if isinstance(insn, InsnSnapshot):
        return _forward_eval_instruction_sequence(
            project_instruction_sequence(insn),
            stk_map,
            reg_map,
            state_var_stkoff,
            diag_lines=diag_lines,
            state_var_gaddr=state_var_gaddr,
            foldable_global_reads=foldable_global_reads,
            fetch_stable_global_value=fetch,
        )

    raise TypeError(
        "state_write.forward_eval_insn requires a canonical Instruction "
        "or lifted InsnSnapshot; backend callers must capture live instructions first"
    )
