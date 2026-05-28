from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import MopSnapshot, OperandKind
from d810.recon.flow.conditional_chain_discovery import (
    extract_check_constant_from_snapshot,
    find_conditional_predecessor,
    get_successor_into_dispatcher,
    resolve_conditional_chain_target,
)


class _DummyFlowGraph:
    def __init__(self, blocks: dict[int, object]):
        self._blocks = blocks
        self.block_count = len(blocks)

    def get_block(self, serial: int):
        return self._blocks.get(int(serial))


def _block(
    serial: int,
    *,
    npred: int = 0,
    preds: tuple[int, ...] = (),
    nsucc: int = 0,
    succs: tuple[int, ...] = (),
    tail_opcode: int | None = None,
    tail: object | None = None,
):
    return SimpleNamespace(
        serial=serial,
        npred=npred,
        preds=preds,
        nsucc=nsucc,
        succs=succs,
        tail_opcode=tail_opcode,
        tail=tail,
    )


def _numeric_check_tail(*, opcode: int, check_value: int, jump_target: int):
    return SimpleNamespace(
        opcode=opcode,
        l=SimpleNamespace(t=0),
        r=MopSnapshot(kind=OperandKind.NUMBER, value=check_value, size=4),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=jump_target),
    )


def test_find_conditional_predecessor_walks_single_pred_chain():
    fg = _DummyFlowGraph(
        {
            10: _block(10, npred=1, preds=(5,)),
            5: _block(5, nsucc=2, succs=(20, 21), tail_opcode=0x99),
        }
    )

    assert find_conditional_predecessor(10, fg, conditional_opcodes=(0x99,)) == 5


def test_extract_check_constant_from_snapshot_reads_numeric_rhs():
    tail = _numeric_check_tail(opcode=0x99, check_value=7, jump_target=20)

    assert extract_check_constant_from_snapshot(
        tail,
        normalize_reversed_jump_opcode=lambda opcode: opcode + 1,
    ) == (0x99, 7, 4)


def test_resolve_conditional_chain_target_follows_jump_and_fallthrough():
    tail = _numeric_check_tail(opcode=0x99, check_value=1, jump_target=20)
    fg = _DummyFlowGraph(
        {
            5: _block(5, nsucc=2, succs=(20, 21), tail_opcode=0x99, tail=tail),
            20: _block(20),
            21: _block(21),
        }
    )

    def is_jump_taken(check_opcode, state_value, check_const, check_size):
        assert (check_opcode, check_const, check_size) == (0x99, 1, 4)
        return state_value == 1

    assert resolve_conditional_chain_target(
        5,
        1,
        fg,
        conditional_opcodes=(0x99,),
        normalize_reversed_jump_opcode=lambda opcode: opcode,
        is_jump_taken_for_state=is_jump_taken,
    ) == 20
    assert resolve_conditional_chain_target(
        5,
        2,
        fg,
        conditional_opcodes=(0x99,),
        normalize_reversed_jump_opcode=lambda opcode: opcode,
        is_jump_taken_for_state=is_jump_taken,
    ) == 21


def test_get_successor_into_dispatcher_prefers_dispatcher_successor():
    fg = _DummyFlowGraph(
        {
            10: _block(10, nsucc=2, succs=(30, 40)),
            30: _block(30, succs=(50,)),
            40: _block(40, succs=(99,)),
        }
    )

    assert get_successor_into_dispatcher({99}, fg, 10) == 40
