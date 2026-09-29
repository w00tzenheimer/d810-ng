"""Fail-closed admission for tail-goto cleanup on cloned microcode."""

from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.passes.tail_goto_merge import (
    TAIL_GOTO_MERGE_METADATA_KEY,
    TailGotoMergeCandidate,
    collect_tail_goto_merge_candidates,
    extract_tail_goto_merge_candidates,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    tail_ea: int | None = None,
) -> BlockSnapshot:
    insns = ()
    if tail_ea is not None:
        target = MopSnapshot(kind=OperandKind.BLOCK, block_ref=succs[0])
        insns = (
            InsnSnapshot(
                opcode=0x200,
                ea=tail_ea,
                operands=(target,),
                d=target,
                kind=InsnKind.GOTO,
            ),
        )
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x401000 + serial,
        insn_snapshots=insns,
    )


def test_cloned_tail_gotos_with_same_ea_are_not_nopped() -> None:
    # The native hash-bound fixture has two one-way blocks with the same tail
    # EA. NOPing both caused the observer to lose an effectful reachable block.
    candidates = [
        {"block_serial": 1, "successor_serial": 2, "insn_ea": 0x405AB6},
        {"block_serial": 3, "successor_serial": 4, "insn_ea": 0x405AB6},
    ]
    graph = FlowGraph(
        blocks={
            0: _block(0, (1, 3), ()),
            1: _block(1, (2,), (0,), tail_ea=0x405AB6),
            2: _block(2, (), (1,)),
            3: _block(3, (4,), (0,), tail_ea=0x405AB6),
            4: _block(4, (), (3,)),
        },
        entry_serial=0,
        func_ea=0x401000,
        metadata={TAIL_GOTO_MERGE_METADATA_KEY: candidates},
    )

    assert collect_tail_goto_merge_candidates(graph) == ()
    assert extract_tail_goto_merge_candidates(graph) == ()


def test_unique_tail_goto_is_still_admitted() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(0, (1,), ()),
            1: _block(1, (2,), (0,), tail_ea=0x405AB6),
            2: _block(2, (), (1,)),
        },
        entry_serial=0,
        func_ea=0x401000,
    )

    assert collect_tail_goto_merge_candidates(graph) == (
        TailGotoMergeCandidate(1, 2, 0x405AB6),
    )
