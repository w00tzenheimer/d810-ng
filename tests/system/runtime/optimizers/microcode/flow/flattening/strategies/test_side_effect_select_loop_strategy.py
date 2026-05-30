"""Runtime tests for side-effect selector-loop cleanup."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from d810.cfg.flowgraph import (
    BranchPredicate,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.cfg.graph_modification import DuplicateBlock, RedirectGoto
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import FAMILY_CLEANUP
from d810.optimizers.microcode.flow.flattening.strategies.side_effect_select_loop import (
    SideEffectSelectLoopStrategy,
)
from d810.analyses.control_flow.side_effect_select_loop import (
    SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY,
    SideEffectSelectLoopFix,
    collect_side_effect_select_loop_fixes,
    extract_side_effect_select_loop_fixes,
    serialize_side_effect_select_loop_fixes,
)


INIT = 0xF4F94852
DEFAULT_ARM = 0x8BB78DF7
COPY_ARM = 0x349E12AF
REALLOC_ARM = 0xC3400665
DIRECT_INIT = 0x62CE9A1C
DIRECT_EXIT_ARM = 0xDD6E5D96
DIRECT_PAYLOAD_ARM = 0x0FCD789F
DIRECT_LOW_LIMIT = 0x0FCD789E


def _reg(reg: int, size: int = 4) -> MopSnapshot:
    return MopSnapshot(t=1, size=size, reg=reg, kind=OperandKind.REGISTER)


def _num(value: int) -> MopSnapshot:
    return MopSnapshot(t=2, size=4, value=value, kind=OperandKind.NUMBER)


def _subinsn() -> MopSnapshot:
    return MopSnapshot(t=4, size=8, kind=OperandKind.SUBINSN)


def _blk(serial: int) -> MopSnapshot:
    return MopSnapshot(t=7, size=-1, block_ref=serial, kind=OperandKind.BLOCK)


def _rich_blk(serial: int) -> SimpleNamespace:
    return SimpleNamespace(block_num=serial)


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
        opcode=19,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", src), ("d", dst)),
        l=src,
        d=dst,
        kind=InsnKind.XDU,
    )


def _jz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    target_operand = _rich_blk(target)
    return InsnSnapshot(
        opcode=44,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", target_operand)),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.EQUALITY_JUMP,
        branch_predicate=BranchPredicate.EQUAL,
    )


def _jnz(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    target_operand = _rich_blk(target)
    return InsnSnapshot(
        opcode=43,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", target_operand)),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
        branch_predicate=BranchPredicate.NOT_EQUAL,
    )


def _jle(left: MopSnapshot, right: MopSnapshot, target: int) -> InsnSnapshot:
    target_operand = _rich_blk(target)
    return InsnSnapshot(
        opcode=52,
        ea=0x1000,
        operands=(),
        operand_slots=(("l", left), ("r", right), ("d", target_operand)),
        l=left,
        r=right,
        d=_blk(target),
        kind=InsnKind.COND_JUMP,
        branch_predicate=BranchPredicate.SIGNED_LE,
    )


def _payload() -> InsnSnapshot:
    return InsnSnapshot(
        opcode=14,
        ea=0x1000,
        operands=(),
        kind=InsnKind.ADD,
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


def _selector_loop_cfg() -> FlowGraph:
    selector = _reg(30)
    state = _reg(31)
    previous = _reg(32)
    blocks = {
        4: _block(4, (6,), (), _mov(_num(DEFAULT_ARM), selector)),
        5: _block(5, (6,), (), _mov(_num(COPY_ARM), selector)),
        6: _block(6, (9,), (4, 5), _mov(_num(INIT), state)),
        8: _block(8, (9,), (10,), _payload()),
        9: _block(
            9,
            (10, 15),
            (6, 8, 14),
            _mov(state, previous),
            _mov(selector, state),
            _jz(previous, _num(INIT), 10),
        ),
        10: _block(10, (8, 12), (9,), _jnz(state, _num(COPY_ARM), 8)),
        12: _block(12, (13,), (10,), _payload()),
        13: _block(13, (14,), (12,)),
        14: _block(14, (9,), (13,), _payload()),
        15: _block(15, (), (9,), _payload()),
    }
    return FlowGraph(blocks=blocks, entry_serial=4, func_ea=0x1000)


def _latched_selector_loop_cfg() -> FlowGraph:
    selector = _reg(30)
    state = _reg(31)
    current = _reg(32)
    carrier = _reg(33, size=8)
    blocks = {
        21: _block(21, (22, 23), (), _mov(_num(COPY_ARM), selector)),
        22: _block(22, (23,), (21,), _mov(_num(REALLOC_ARM), selector)),
        23: _block(23, (26,), (21, 22), _mov(_num(INIT), state)),
        24: _block(24, (25, 33), (26,), _jnz(current, _num(REALLOC_ARM), 33)),
        25: _block(
            25,
            (26,),
            (24,),
            _mov(_subinsn(), carrier),
            _mov(_num(DEFAULT_ARM), state),
        ),
        26: _block(
            26,
            (27, 24),
            (23, 25, 28, 29, 32, 33),
            _xdu(state, current),
            _mov(carrier, carrier),
            _jle(state, _num((INIT - 1) & 0xFFFFFFFF), 24),
        ),
        27: _block(27, (28, 30), (26,), _jz(current, _num(COPY_ARM), 30)),
        28: _block(
            28,
            (29, 26),
            (27,),
            _mov(current, state),
            _jnz(current, _num(INIT), 26),
        ),
        29: _block(29, (26,), (28,), _mov(_num(INIT), current), _mov(selector, state)),
        30: _block(30, (32,), (27,), _payload()),
        32: _block(32, (26,), (30,), _payload(), _mov(_num(DEFAULT_ARM), state)),
        33: _block(
            33,
            (26, 34),
            (24,),
            _xdu(current, state),
            _jnz(current, _num(DEFAULT_ARM), 26),
        ),
        34: _block(34, (), (33,), _payload()),
    }
    return FlowGraph(blocks=blocks, entry_serial=21, func_ea=0x1000)


def _direct_exit_selector_loop_cfg() -> FlowGraph:
    selector = _reg(40)
    state = _reg(41)
    previous = _reg(42)
    blocks = {
        4: _block(4, (6,), (), _mov(_num(DIRECT_EXIT_ARM), selector)),
        5: _block(5, (6,), (), _mov(_num(DIRECT_PAYLOAD_ARM), selector)),
        6: _block(6, (7,), (4, 5), _mov(_num(DIRECT_INIT), state)),
        7: _block(
            7,
            (8, 12),
            (6, 8, 9),
            _mov(state, previous),
            _jle(state, _num(DIRECT_LOW_LIMIT), 12),
        ),
        8: _block(
            8,
            (9, 7),
            (7,),
            _mov(selector, state),
            _jz(previous, _num(DIRECT_INIT), 7),
        ),
        9: _block(
            9,
            (10, 7),
            (8,),
            _mov(previous, state),
            _jnz(previous, _num(DIRECT_PAYLOAD_ARM), 7),
        ),
        10: _block(10, (12,), (9,), _payload()),
        12: _block(12, (), (7, 10), _payload()),
    }
    return FlowGraph(blocks=blocks, entry_serial=4, func_ea=0x1000)


def test_collect_side_effect_select_loop_fixes_proves_pred_armed_shell() -> None:
    assert collect_side_effect_select_loop_fixes(_selector_loop_cfg()) == (
        SideEffectSelectLoopFix(
            init_block=6,
            header_block=9,
            per_pred_targets=((4, 8), (5, 12)),
            terminal_redirects=((8, 9, 15), (14, 9, 15)),
        ),
    )


def test_collect_side_effect_select_loop_fixes_proves_latched_selector_shell() -> None:
    assert collect_side_effect_select_loop_fixes(_latched_selector_loop_cfg()) == (
        SideEffectSelectLoopFix(
            init_block=23,
            header_block=26,
            per_pred_targets=((21, 30), (22, 25)),
            terminal_redirects=((25, 26, 34), (32, 26, 34)),
        ),
    )


def test_collect_side_effect_select_loop_fixes_proves_direct_exit_shell() -> None:
    assert collect_side_effect_select_loop_fixes(_direct_exit_selector_loop_cfg()) == (
        SideEffectSelectLoopFix(
            init_block=6,
            header_block=7,
            per_pred_targets=((4, 12), (5, 10)),
            terminal_redirects=(),
        ),
    )


def test_side_effect_select_loop_strategy_plans_duplicate_and_terminal_exits() -> None:
    cfg = _selector_loop_cfg()
    fixes = collect_side_effect_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY: (
                serialize_side_effect_select_loop_fixes(fixes)
            )
        },
    )

    fragment = SideEffectSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.strategy_name == "side_effect_select_loop"
    assert fragment.family == FAMILY_CLEANUP
    assert fragment.ownership.blocks == frozenset({6, 8, 14})
    assert fragment.ownership.edges == frozenset({(4, 6), (5, 6), (8, 9), (14, 9)})
    assert fragment.modifications == [
        DuplicateBlock(
            source_block=6,
            target_block=8,
            pred_serial=4,
            patch_kind="side_effect_select_loop",
        ),
        DuplicateBlock(
            source_block=6,
            target_block=12,
            pred_serial=5,
            patch_kind="side_effect_select_loop",
        ),
        RedirectGoto(from_serial=8, old_target=9, new_target=15),
        RedirectGoto(from_serial=14, old_target=9, new_target=15),
    ]


def test_side_effect_select_loop_strategy_plans_direct_exit_duplication() -> None:
    cfg = _direct_exit_selector_loop_cfg()
    fixes = collect_side_effect_select_loop_fixes(cfg)
    cfg = replace(
        cfg,
        metadata={
            SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY: (
                serialize_side_effect_select_loop_fixes(fixes)
            )
        },
    )

    fragment = SideEffectSelectLoopStrategy().plan(
        AnalysisSnapshot(mba=object(), flow_graph=cfg),
    )

    assert fragment is not None
    assert fragment.strategy_name == "side_effect_select_loop"
    assert fragment.family == FAMILY_CLEANUP
    assert fragment.ownership.blocks == frozenset({6})
    assert fragment.ownership.edges == frozenset({(4, 6), (5, 6)})
    assert fragment.modifications == [
        DuplicateBlock(
            source_block=6,
            target_block=12,
            pred_serial=4,
            patch_kind="side_effect_select_loop",
        ),
        DuplicateBlock(
            source_block=6,
            target_block=10,
            pred_serial=5,
            patch_kind="side_effect_select_loop",
        ),
    ]


def test_extract_side_effect_select_loop_fixes_rejects_stale_metadata() -> None:
    cfg = _selector_loop_cfg()
    cfg = replace(
        cfg,
        metadata={
            SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY: (
                {
                    "init_block": 6,
                    "header_block": 9,
                    "per_pred_targets": ((4, 8), (5, 12)),
                    "terminal_redirects": ((8, 99, 15), (14, 9, 15)),
                },
            )
        },
    )

    assert extract_side_effect_select_loop_fixes(cfg) == ()


def test_extract_side_effect_select_loop_fixes_rejects_wrong_pred_targets() -> None:
    cfg = _selector_loop_cfg()
    cfg = replace(
        cfg,
        metadata={
            SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY: (
                {
                    "init_block": 6,
                    "header_block": 9,
                    "per_pred_targets": ((4, 12), (5, 8)),
                    "terminal_redirects": ((8, 9, 15), (14, 9, 15)),
                },
            )
        },
    )

    assert extract_side_effect_select_loop_fixes(cfg) == ()
