"""Branch-witness providers for dispatcher projection.

Providers produce explicit per-compare witness rows. They may use recovered
dispatcher metadata to find states, dispatcher blocks, and the entry compare,
but endpoint rows are not proof: selected and rejected arms are derived from
the current CFG and validated later by :func:`static_witness_for_state`.
"""
from __future__ import annotations

from d810.analyses.control_flow.branch_witness import (
    BranchWitnessMap,
    BranchWitnessRow,
    ExactBranchWitness,
    _block_compare_operands,
    _compare_successors,
    _evaluate_branch,
    _int_or_none,
    _is_known_predicate,
    _predicate_value,
    static_witness_for_state,
)
from d810.capabilities.dispatcher import RouterKind


def build_static_equality_chain_witness_map(
    flow_graph: object,
    dispatch_map: object,
    *,
    states: tuple[int, ...] | None = None,
) -> BranchWitnessMap | None:
    """Build static per-compare witness rows for a conditional-chain dispatcher.

    The returned rows describe selected/rejected compare arms. The
    ``StateDispatcherMap`` endpoint rows are used only to enumerate candidate
    states and dispatcher metadata; row target blocks are deliberately ignored.
    """

    if getattr(dispatch_map, "source", None) is not RouterKind.CONDITION_CHAIN:
        return None
    entry = _int_or_none(getattr(dispatch_map, "dispatcher_entry_block", None))
    if entry is None:
        return None
    dispatcher_blocks = frozenset(
        int(b) for b in getattr(dispatch_map, "dispatcher_blocks", ()) if b is not None
    )
    if not dispatcher_blocks:
        return None
    if states is None:
        states = tuple(
            int(getattr(row, "state_const"))
            for row in getattr(dispatch_map, "rows", ())
            if _int_or_none(getattr(row, "state_const", None)) is not None
        )
    if not states:
        return None

    rows: list[BranchWitnessRow] = []
    seen: set[tuple[int, int]] = set()
    for state in states:
        state_u = int(state) & 0xFFFFFFFF
        current = int(entry)
        visited: set[int] = set()
        while current in dispatcher_blocks:
            if current in visited:
                break
            visited.add(current)
            block = flow_graph.get_block(current)
            if block is None:
                break
            tail = getattr(block, "tail", None)
            if tail is None or not getattr(tail, "is_conditional_jump", False):
                break
            predicate = _predicate_value(getattr(tail, "branch_predicate", None))
            if not _is_known_predicate(predicate):
                break
            compare_const, _state_op = _block_compare_operands(block)
            if compare_const is None:
                break
            taken, fallthrough = _compare_successors(block)
            if taken is None or fallthrough is None:
                break
            evaluated = _evaluate_branch(
                predicate, state_u, int(compare_const), int(taken), int(fallthrough)
            )
            if evaluated is None:
                break
            selected, rejected = evaluated
            key = (state_u, int(current))
            if key not in seen:
                seen.add(key)
                rows.append(
                    BranchWitnessRow(
                        state=state_u,
                        compare_block=int(current),
                        predicate=predicate,
                        compare_const=int(compare_const) & 0xFFFFFFFF,
                        selected_successor=int(selected),
                        rejected_successors=tuple(int(r) for r in rejected),
                        source=getattr(dispatch_map, "source", None),
                    )
                )
            if int(selected) not in dispatcher_blocks:
                break
            current = int(selected)

    if not rows:
        return None
    return BranchWitnessMap(
        rows=tuple(rows),
        dispatcher_entry_block=int(entry),
        dispatcher_blocks=dispatcher_blocks,
        state_var_stkoff=_int_or_none(getattr(dispatch_map, "state_var_stkoff", None)),
        source=getattr(dispatch_map, "source", None),
    )


def _mop_references_stack(mop: object, stkoff: int) -> bool:
    if mop is None:
        return False
    direct = _int_or_none(getattr(mop, "stkoff", None))
    if direct is not None and int(direct) == int(stkoff):
        return True
    for ref in getattr(mop, "stack_refs", ()) or ():
        ref_i = _int_or_none(ref)
        if ref_i is not None and int(ref_i) == int(stkoff):
            return True
    for attr in ("sub_l", "sub_r", "sub_operand"):
        if _mop_references_stack(getattr(mop, attr, None), stkoff):
            return True
    sub_insn = getattr(mop, "sub_instruction", None)
    if sub_insn is not None:
        return any(
            _mop_references_stack(getattr(sub_insn, attr, None), stkoff)
            for attr in ("l", "r", "d")
        )
    return False


def _mop_const_value(mop: object) -> int | None:
    if mop is None:
        return None
    kind = getattr(getattr(mop, "kind", None), "value", getattr(mop, "kind", None))
    if kind == "number" or getattr(mop, "value", None) is not None:
        return _int_or_none(getattr(mop, "value", None))
    return None


def _insn_references_stack(insn: object, stkoff: int) -> bool:
    return any(
        _mop_references_stack(getattr(insn, attr, None), stkoff)
        for attr in ("l", "r", "d")
    )


def _is_indirect_store(insn: object) -> bool:
    kind = getattr(getattr(insn, "kind", None), "value", getattr(insn, "kind", None))
    opcode_name = str(getattr(insn, "opcode_name", "") or "").lower()
    text = str(getattr(insn, "display_text", "") or getattr(insn, "dstr", "") or "")
    is_store = (
        kind == "store"
        or opcode_name in {"m_stx", "op_1", "store"}
        or text.lstrip().startswith("stx ")
    )
    if not is_store:
        return False
    dest = getattr(insn, "d", None)
    return _int_or_none(getattr(dest, "reg", None)) is not None


def block_has_unresolved_indirect_state_store(
    block: object,
    state_var_stkoff: int | None,
) -> bool:
    """Return whether a block carries pointer-indirected state stores."""

    if state_var_stkoff is None:
        return False
    tail = getattr(block, "tail", None)
    if tail is None or not _insn_references_stack(tail, int(state_var_stkoff)):
        return False
    for insn in tuple(getattr(block, "insn_snapshots", ()) or ())[:-1]:
        if _is_indirect_store(insn):
            return True
    return False


def _local_compare_witness_row(
    block: object,
    block_serial: int,
    state_value: int,
    compare_const: int,
) -> BranchWitnessRow | None:
    tail = getattr(block, "tail", None)
    if tail is None or not getattr(tail, "is_conditional_jump", False):
        return None
    predicate = _predicate_value(getattr(tail, "branch_predicate", None))
    if predicate not in {"eq", "ne"}:
        return None
    taken, fallthrough = _compare_successors(block)
    if taken is None or fallthrough is None:
        return None
    state_u = int(state_value) & 0xFFFFFFFF
    const_u = int(compare_const) & 0xFFFFFFFF
    evaluated = _evaluate_branch(predicate, state_u, const_u, taken, fallthrough)
    if evaluated is None:
        return None
    selected, rejected = evaluated
    return BranchWitnessRow(
        state=state_u,
        compare_block=int(block_serial),
        predicate=predicate,
        compare_const=const_u,
        selected_successor=int(selected),
        rejected_successors=tuple(int(r) for r in rejected),
        evidence="local_indirect_state_store_compare",
    )


def indirect_state_store_branch_witness(
    flow_graph: object,
    block: object,
    block_serial: int,
    state_var_stkoff: int | None,
    branch_witness_map: object | None,
) -> ExactBranchWitness | None:
    """Prove the selected successor after an indirect concrete state store."""

    if state_var_stkoff is None:
        return None
    tail = getattr(block, "tail", None)
    if tail is None or not _insn_references_stack(tail, int(state_var_stkoff)):
        return None
    compare_const = None
    for operand in (getattr(tail, "l", None), getattr(tail, "r", None)):
        compare_const = _mop_const_value(operand)
        if compare_const is not None:
            break
    if compare_const is None:
        return None

    stored_consts: set[int] = set()
    for insn in tuple(getattr(block, "insn_snapshots", ()) or ())[:-1]:
        if not _is_indirect_store(insn):
            continue
        value = _mop_const_value(getattr(insn, "l", None))
        if value is not None:
            stored_consts.add(int(value) & 0xFFFFFFFF)
    compare_u = int(compare_const) & 0xFFFFFFFF
    if compare_u not in stored_consts:
        return None

    row = None
    row_for = getattr(branch_witness_map, "row_for_state_compare", None)
    if callable(row_for):
        row = row_for(compare_u, int(block_serial))
    if row is None:
        row = _local_compare_witness_row(
            block, int(block_serial), compare_u, compare_u
        )
        if row is None:
            return None
    witness = static_witness_for_state(
        flow_graph, row, compare_u, int(state_var_stkoff)
    )
    if isinstance(witness, ExactBranchWitness):
        return witness
    return None


__all__ = [
    "block_has_unresolved_indirect_state_store",
    "build_static_equality_chain_witness_map",
    "indirect_state_store_branch_witness",
]
