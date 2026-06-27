"""Branch-witness providers for dispatcher projection.

Providers produce explicit per-compare witness rows. They may use recovered
dispatcher metadata to find states, dispatcher blocks, and the entry compare,
but endpoint rows are not proof: selected and rejected arms are derived from
the current CFG and validated later by :func:`static_witness_for_state`.

d81-qlal -- canonical Instruction port.  The compare / indirect-store readers no
longer touch backend-shaped ``InsnSnapshot`` operand slots (``.l`` / ``.r`` /
``.d``) or the dead text-fallback probes (``opcode_name`` / ``dstr`` /
``sub_operand`` / ``sub_instruction``, none of which is a field on either the
portable or the rich ``MopSnapshot`` / ``InsnSnapshot``).  Inputs are
strong-typed against the portable :class:`~d810.ir.flowgraph.FlowGraph` /
:class:`~d810.analyses.control_flow.dispatcher_resolution.StateDispatcherMap` /
:class:`~d810.ir.flowgraph.BlockSnapshot` / ``InsnSnapshot`` / ``MopSnapshot``
models:

* the conditional jump target / branch predicate / compared constant are read
  off the canonical :func:`~d810.ir.insn_projection.project_instruction`
  projection (``Instruction.control`` and ``operand_storages``);
* an instruction's stack-variable references are read off the lift-boundary
  :func:`~d810.ir.insn_projection.operand_stack_offsets` /
  :func:`~d810.ir.insn_projection.operand_stack_refs` accessors plus the portable
  ``MopSnapshot.stack_refs`` / ``sub_l`` / ``sub_r`` / ``args`` expression tree;
* an indirect (pointer-register-dest) store is identified from the canonical
  ``Instruction`` STORE memory access whose target is a register
  (was ``opcode_name == "m_stx"`` text + ``insn.d.reg``).
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
    _tail_predicate_value,
    static_witness_for_state,
)
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnSnapshot,
    MopSnapshot,
)
from d810.ir.insn_projection import (
    operand_stack_offsets,
    operand_stack_refs,
    operand_storages,
    project_instruction,
)
from d810.ir.storage_identity import (
    StorageIdentityKind,
    storage_identity_from_mop_snapshot,
)
from d810.ir.varnode import Space, Varnode


def build_static_equality_chain_witness_map(
    flow_graph: FlowGraph,
    dispatch_map: StateDispatcherMap,
    *,
    states: tuple[int, ...] | None = None,
) -> BranchWitnessMap | None:
    """Build static per-compare witness rows for a conditional-chain dispatcher.

    The returned rows describe selected/rejected compare arms. The
    ``StateDispatcherMap`` endpoint rows are used only to enumerate candidate
    states and dispatcher metadata; row target blocks are deliberately ignored.
    """

    if dispatch_map.router_kind is not RouterKind.CONDITION_CHAIN:
        return None
    entry = _int_or_none(dispatch_map.dispatcher_entry_block)
    if entry is None:
        return None
    dispatcher_blocks = frozenset(
        int(b) for b in dispatch_map.dispatcher_blocks if b is not None
    )
    if not dispatcher_blocks:
        return None
    if states is None:
        states = tuple(
            int(row.state_const)
            for row in dispatch_map.rows
            if _int_or_none(row.state_const) is not None
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
            tail = block.tail
            if tail is None or not tail.is_conditional_jump:
                break
            predicate = _tail_predicate_value(block)
            if predicate is None or not _is_known_predicate(predicate):
                break
            compare_const, _state_slot = _block_compare_operands(block)
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
                        router_kind=dispatch_map.router_kind,
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
        state_var_stkoff=_int_or_none(dispatch_map.state_var_stkoff),
        router_kind=dispatch_map.router_kind,
    )


def _mop_references_stack(mop: MopSnapshot | None, stkoff: int) -> bool:
    """Whether a portable operand snapshot references stack cell ``stkoff``.

    Reads only portable ``MopSnapshot`` identity / expression-tree fields: the
    direct storage identity, the flattened ``stack_refs``, and the nested
    ``sub_l`` / ``sub_r`` / ``args`` operands.  The legacy ``sub_operand`` /
    ``sub_instruction`` probes were dead (neither is a field on the portable or
    the rich snapshot) and are removed.
    """
    if mop is None:
        return False
    identity = storage_identity_from_mop_snapshot(mop)
    if (
        identity is not None
        and identity.kind is StorageIdentityKind.STACK
        and int(identity.offset) == int(stkoff)
    ):
        return True
    for ref in mop.stack_refs or ():
        ref_i = _int_or_none(ref)
        if ref_i is not None and int(ref_i) == int(stkoff):
            return True
    for child in (mop.sub_l, mop.sub_r, *mop.args):
        if _mop_references_stack(child, stkoff):
            return True
    return False


def _insn_references_stack(insn: InsnSnapshot, stkoff: int) -> bool:
    """Whether any compare/dest operand of ``insn`` references stack ``stkoff``.

    Read off the canonical lift-boundary stack accessors (named offset +
    flattened expression-tree refs), never the raw ``insn.l`` / ``insn.r`` /
    ``insn.d`` operand slots.
    """
    target = int(stkoff)
    if any(named is not None and int(named) == target for named in operand_stack_offsets(insn)):
        return True
    return any(target in refs for refs in operand_stack_refs(insn))


def _is_indirect_store(insn: InsnSnapshot) -> bool:
    """Whether ``insn`` is a pointer-register-indirected store.

    Identified from the canonical projection: a STORE whose memory-access target
    is a register ``Varnode`` (the legacy ``insn.d.reg is not None`` pointer
    register), via the portable ``Instruction.memory`` / effects.  The
    ``opcode_name`` / ``dstr`` text fallbacks were dead and are removed.
    """
    instruction = project_instruction(insn)
    memory = instruction.memory
    target: Varnode | None = memory.target if memory is not None else None
    return target is not None and target.space is Space.REGISTER


def block_has_unresolved_indirect_state_store(
    block: BlockSnapshot,
    state_var_stkoff: int | None,
) -> bool:
    """Return whether a block carries pointer-indirected state stores."""

    if state_var_stkoff is None:
        return False
    tail = block.tail
    if tail is None or not _insn_references_stack(tail, int(state_var_stkoff)):
        return False
    for insn in block.insn_snapshots[:-1]:
        if _is_indirect_store(insn):
            return True
    return False


def _local_compare_witness_row(
    block: BlockSnapshot,
    block_serial: int,
    state_value: int,
    compare_const: int,
) -> BranchWitnessRow | None:
    tail = block.tail
    if tail is None or not tail.is_conditional_jump:
        return None
    predicate = _tail_predicate_value(block)
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


def _tail_compare_const(tail: InsnSnapshot) -> int | None:
    """Return the numeric constant compared in a conditional-jump tail, else None.

    Reads the slot-aligned ``operand_storages`` views (a ``NUMBER`` operand
    projects to a ``Varnode(Space.CONST, value)``), left-first then right --
    never the raw ``tail.l`` / ``tail.r`` operand slot.
    """
    left, right, _dest = operand_storages(tail)
    for storage in (left, right):
        if isinstance(storage, Varnode) and storage.space is Space.CONST:
            return int(storage.offset) & 0xFFFFFFFF
    return None


def _indirect_store_const(insn: InsnSnapshot) -> int | None:
    """Return the constant value an indirect store writes, else ``None``.

    The stored value is the STORE's value operand (was ``insn.l``); read off the
    canonical ``Instruction`` memory access / store effect as a ``CONST``
    ``Varnode``.
    """
    instruction = project_instruction(insn)
    value: Varnode | None = None
    memory = instruction.memory
    if memory is not None:
        value = memory.value
    if value is None:
        for effect in instruction.effects:
            if effect.value is not None:
                value = effect.value
                break
    if value is not None and value.space is Space.CONST:
        return int(value.offset) & 0xFFFFFFFF
    return None


def indirect_state_store_branch_witness(
    flow_graph: FlowGraph,
    block: BlockSnapshot,
    block_serial: int,
    state_var_stkoff: int | None,
    branch_witness_map: BranchWitnessMap | None,
) -> ExactBranchWitness | None:
    """Prove the selected successor after an indirect concrete state store."""

    if state_var_stkoff is None:
        return None
    tail = block.tail
    if tail is None or not _insn_references_stack(tail, int(state_var_stkoff)):
        return None
    compare_const = _tail_compare_const(tail)
    if compare_const is None:
        return None

    stored_consts: set[int] = set()
    for insn in block.insn_snapshots[:-1]:
        if not _is_indirect_store(insn):
            continue
        value = _indirect_store_const(insn)
        if value is not None:
            stored_consts.add(int(value) & 0xFFFFFFFF)
    compare_u = int(compare_const) & 0xFFFFFFFF
    if compare_u not in stored_consts:
        return None

    row: BranchWitnessRow | None = None
    if branch_witness_map is not None:
        row = branch_witness_map.row_for_state_compare(compare_u, int(block_serial))
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
