"""Runtime tests for local constant-select loop cleanup."""
from __future__ import annotations

from dataclasses import replace

from d810.cfg.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.cfg.graph_modification import RedirectBranch, RedirectGoto
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import FAMILY_CLEANUP
from d810.optimizers.microcode.flow.flattening.strategies.local_select_loop import (
    LOCAL_SELECT_LOOP_FIXES_METADATA_KEY,
    LocalSelectLoopFix,
    LocalSelectLoopStrategy,
    collect_local_select_loop_fixes,
    extract_local_select_loop_fixes,
    serialize_local_select_loop_fixes,
)


INIT = 0x1BD0B1A
SELECT = 0xCF87A00D
DONE = 0xBCF37D88


def _reg(reg: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(t=1, size=size, reg=reg, kind=OperandKind.REGISTER)


def _num(value: int) -> MopSnapshot:
    return MopSnapshot(t=2, size=4, value=value, kind=OperandKind.NUMBER)


def _blk(serial: int) -> MopSnapshot:
    return MopSnapshot(t=7, size=-1, block_ref=serial, kind=OperandKind.BLOCK)


def _mov(src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=4,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", src), ("d", dst)),
        l=src,
        d=dst,
        kind=InsnKind.MOV,
    )


def _xdu(src: MopSnapshot, dst: MopSnapshot) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=9,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", src), ("d", dst)),
        l=src,
        d=dst,
        kind=InsnKind.XDU,
    )


def _jz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=44,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.EQUALITY_JUMP,
    )


def _jnz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=43,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", _blk(target))),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
    )


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *insns: InsnSnapshot,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=4 if len(succs) == 2 else 1 if len(succs) == 1 else 2,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=tuple(insns),
    )


def _select_loop_cfg(*, widened_previous: bool = False) -> FlowGraph:
    selector = _reg(34)
    state = _reg(36)
    previous = _reg(37, size=8 if widened_previous else 4)
    previous_cmp = _reg(37)
    default_value = _reg(29, 8)
    selected_value = _reg(30, 8)
    output = _reg(35, 8)
    blocks = {
        17: _block(
            17,
            (20,),
            (15, 16),
            _mov(default_value, output),
            _mov(_num(INIT), state),
        ),
        18: _block(18, (19, 20), (20,), _jnz(selector, _num(SELECT), 20)),
        19: _block(
            19,
            (20,),
            (18,),
            _mov(selected_value, output),
            _mov(_num(DONE), state),
        ),
        20: _block(
            20,
            (21, 18),
            (17, 18, 19),
            _xdu(state, previous) if widened_previous else _mov(state, previous),
            _mov(selector, state),
            _jz(previous_cmp, _num(INIT), 18),
        ),
        21: _block(21, (), (20,)),
    }
    return FlowGraph(blocks=blocks, entry_serial=17, func_ea=0x1000)


def test_collect_local_select_loop_fixes_proves_one_iteration_shell() -> None:
    assert collect_local_select_loop_fixes(_select_loop_cfg()) == (
        LocalSelectLoopFix(
            init_block=17,
            init_old_target=20,
            test_block=18,
            test_old_target=20,
            assignment_block=19,
            assignment_old_target=20,
            exit_target=21,
        ),
    )


def test_collect_local_select_loop_fixes_accepts_widened_previous_copy() -> None:
    assert collect_local_select_loop_fixes(
        _select_loop_cfg(widened_previous=True)
    ) == (
        LocalSelectLoopFix(
            init_block=17,
            init_old_target=20,
            test_block=18,
            test_old_target=20,
            assignment_block=19,
            assignment_old_target=20,
            exit_target=21,
        ),
    )


def test_local_select_loop_strategy_plans_redirects() -> None:
    cfg = _select_loop_cfg()
    fixes = collect_local_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: serialize_local_select_loop_fixes(
                fixes
            )
        },
    )

    fragment = LocalSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.strategy_name == "local_select_loop"
    assert fragment.family == FAMILY_CLEANUP
    assert fragment.ownership.blocks == frozenset({17, 18, 19})
    assert fragment.ownership.edges == frozenset({(17, 20), (18, 20), (19, 20)})
    assert fragment.modifications == [
        RedirectBranch(from_serial=18, old_target=20, new_target=21),
        RedirectGoto(from_serial=19, old_target=20, new_target=21),
        RedirectGoto(from_serial=17, old_target=20, new_target=18),
    ]


def test_extract_local_select_loop_fixes_rejects_stale_metadata() -> None:
    cfg = _select_loop_cfg()
    cfg = replace(
        cfg,
        metadata={
            LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: (
                {
                    "init_block": 17,
                    "init_old_target": 99,
                    "test_block": 18,
                    "test_old_target": 20,
                    "assignment_block": 19,
                    "assignment_old_target": 20,
                    "exit_target": 21,
                },
            )
        },
    )

    assert extract_local_select_loop_fixes(cfg) == ()
