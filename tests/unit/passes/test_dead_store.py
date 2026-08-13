from __future__ import annotations

from types import SimpleNamespace

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.passes.dead_store import (
    DeadStoreEliminationStrategy,
    build_dead_store_modifications,
    collect_dead_store_candidates,
)
from d810.transforms.graph_modification import RemoveInstruction


def _reg(register: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(
        t=1,
        size=size,
        reg=register,
        kind=OperandKind.REGISTER,
    )


def _stack(offset: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(
        t=5,
        size=size,
        stkoff=offset,
        kind=OperandKind.STACK,
    )


def _number(value: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(
        t=2,
        size=size,
        value=value,
        kind=OperandKind.NUMBER,
    )


def _lvar(index: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(
        t=8,
        size=size,
        lvar_off=index,
        kind=OperandKind.LVAR,
    )


def _mov(ea: int, source: MopSnapshot, destination: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0x55,
        ea=ea,
        operands=(source, destination),
        l=source,
        d=destination,
        kind=InsnKind.MOV,
    )


def _block(
    serial: int,
    *,
    instructions: tuple[InsnSnapshot, ...],
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x401000 + serial * 0x100,
        insn_snapshots=instructions,
    )


def test_collects_direct_register_write_overwritten_in_same_block() -> None:
    target = _reg(7)
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                instructions=(
                    _mov(0x401000, _number(1), target),
                    _mov(0x401004, _number(2), target),
                ),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    candidates = collect_dead_store_candidates(graph)

    assert len(candidates) == 1
    assert candidates[0].block_serial == 0
    assert candidates[0].ordinal == 0
    assert candidates[0].destination_kind == "register"
    assert candidates[0].destination_id == 7


def test_rejects_write_when_any_successor_path_reads_before_redefinition() -> None:
    target = _reg(7)
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                instructions=(_mov(0x401000, _number(1), target),),
                succs=(1, 2),
            ),
            1: _block(
                1,
                instructions=(_mov(0x401100, target, _reg(8)),),
                preds=(0,),
            ),
            2: _block(
                2,
                instructions=(_mov(0x401200, _number(2), target),),
                preds=(0,),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    assert collect_dead_store_candidates(graph) == ()


def test_rejects_unmapped_lvar_as_a_possible_stack_alias() -> None:
    target = _reg(7)
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                instructions=(
                    _mov(0x401000, _number(1), target),
                    _mov(0x401004, _lvar(0), _reg(8)),
                    _mov(0x401008, _number(2), target),
                ),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    assert collect_dead_store_candidates(graph) == ()


def test_collects_only_when_every_successor_path_redefines_target() -> None:
    target = _reg(7)
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                instructions=(_mov(0x401000, _number(1), target),),
                succs=(1, 2),
            ),
            1: _block(
                1,
                instructions=(_mov(0x401100, _number(2), target),),
                preds=(0,),
            ),
            2: _block(
                2,
                instructions=(_mov(0x401200, _number(3), target),),
                preds=(0,),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    candidates = collect_dead_store_candidates(graph)

    assert len(candidates) == 1
    assert candidates[0].insn_ea == 0x401000


def test_collects_direct_write_when_every_path_exits_without_a_read() -> None:
    target = _stack(44)
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                instructions=(_mov(0x401000, _number(1), target),),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    candidates = collect_dead_store_candidates(graph)

    assert len(candidates) == 1
    assert candidates[0].insn_ea == 0x401000


def test_strategy_emits_fingerprinted_remove_instruction() -> None:
    target = _reg(7)
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                instructions=(
                    _mov(0x401000, _number(1), target),
                    _mov(0x401004, _number(2), target),
                ),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    fragment = DeadStoreEliminationStrategy().plan(
        SimpleNamespace(flow_graph=graph)
    )

    assert fragment is not None
    assert fragment.modifications == [
        RemoveInstruction(
            block_serial=0,
            block_start_ea=0x401000,
            insn_ea=0x401000,
            ordinal=0,
            opcode=0x55,
            destination_kind="register",
            destination_id=7,
            destination_size=8,
        )
    ]


def test_orders_same_block_removals_from_later_to_earlier_ordinals() -> None:
    target = _reg(7)
    graph = FlowGraph(
        blocks={
            0: _block(
                0,
                instructions=(
                    _mov(0x401000, _number(1), target),
                    _mov(0x401004, _number(2), target),
                    _mov(0x401008, _number(3), target),
                    _mov(0x40100C, _number(4), target),
                ),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    modifications = build_dead_store_modifications(collect_dead_store_candidates(graph))

    assert [modification.ordinal for modification in modifications] == [2, 1, 0]
